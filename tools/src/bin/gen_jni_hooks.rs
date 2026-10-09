//! Generates `jni_hooks.h`: the JNI method tables the loader hooks.
//!
//! The header is generated rather than written because the same three zygote
//! methods have dozens of signatures across Android versions and OEM forks, and
//! the hooked body is identical in all of them. Spelling them out by hand is
//! where a typo becomes a crash on one device only.
//!
//! Usage: gen-jni-hooks [output-path]
//!
//! Without an argument the header lands next to this file's crate, which is
//! where the loader includes it from; an explicit path is honoured too, which is
//! what the consistency check in tests/host uses to generate into a scratch
//! directory and compare.
//!
//! The output is compiled into the library, so it is byte-for-byte stable: the
//! committed header has to match what this produces, and the check that enforces
//! it is part of the host suite.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

/// The JNI types this file uses, in the two spellings: the C type in the
/// signature and the JNI descriptor character in the method table.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JType {
    JInt,
    JBoolean,
    JLong,
    JString,
    Void,
    /// `jint *`: an array type is a pointer in C and a bracket in the descriptor.
    Array(&'static JType),
}

impl JType {
    /// The C spelling, which is what appears in a signature.
    ///
    /// An array of a primitive is `jintArray`/`jlongArray`/`jbooleanArray`,
    /// because that is what jni.h declares; every other array is a
    /// `jobjectArray`. Nothing here is spelled `jint *`: the signature has to
    /// name the same type the platform declared, or the two disagree about the
    /// ABI of the call.
    fn cpp(self) -> String {
        match self {
            Self::JInt => "jint".into(),
            Self::JBoolean => "jboolean".into(),
            Self::JLong => "jlong".into(),
            Self::JString => "jstring".into(),
            Self::Void => "void".into(),
            Self::Array(inner) => match inner {
                Self::JInt => "jintArray".into(),
                Self::JLong => "jlongArray".into(),
                Self::JBoolean => "jbooleanArray".into(),
                _ => "jobjectArray".into(),
            },
        }
    }

    /// The JNI descriptor, which is what the method table matches on.
    ///
    /// An array's descriptor is a bracket followed by the *element's* descriptor,
    /// so a two dimensional array is two brackets: `rlimits` is `jintArray[]` in
    /// C and `[[I` here.
    fn descriptor(self) -> String {
        match self {
            Self::JInt => "I".into(),
            Self::JBoolean => "Z".into(),
            Self::JLong => "J".into(),
            Self::JString => "Ljava/lang/String;".into(),
            Self::Void => "V".into(),
            Self::Array(inner) => format!("[{}", inner.descriptor()),
        }
    }
}

/// One parameter of a hooked method.
struct Arg {
    name: String,
    type_: JType,
    /// Whether the body copies this argument into the args struct it builds.
    ///
    /// The struct holds pointers, so a parameter the body does not touch - one
    /// this fork has no use for - must not be wired up: a pointer to it would
    /// dangle once the original method returns.
    set_arg: bool,
}

impl Arg {
    fn new(name: &str, type_: JType) -> Self {
        Self {
            name: name.into(),
            type_,
            set_arg: false,
        }
    }

    /// A parameter the body does not copy anywhere.
    fn anon(type_: JType) -> Self {
        // Named after its position so the generated C keeps a distinct name per
        // ignored parameter, and sorted so the counter below is stable.
        let index = ANON_COUNT.with(|count| {
            let value = count.get();
            count.set(value + 1);
            value
        });

        Self {
            name: format!("_{index}"),
            type_,
            set_arg: false,
        }
    }

    fn set_arg(name: &str, type_: JType) -> Self {
        Self {
            name: name.into(),
            type_,
            set_arg: true,
        }
    }

    fn cpp(&self) -> String {
        format!("{} {}", self.type_.cpp(), self.name)
    }
}

thread_local! {
    /// The anonymous-argument counter.
    ///
    /// Per thread because the generators are pure functions of their inputs, and
    /// a global would make the output depend on what was generated before.
    static ANON_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The return value: an expression, or nothing for a void method.
struct Ret {
    value: Option<&'static str>,
    type_: JType,
}

fn ret(value: Option<&'static str>, type_: JType) -> Ret {
    Ret { value, type_ }
}

/// One hooked method: a version-suffixed name plus its signature.
struct Method {
    name: String,
    ret: Ret,
    args: Vec<Arg>,
    /// The JNI method this one hooks.
    ///
    /// Carried separately from the body shape because
    /// nativeSpecializeAppProcess and nativeForkAndSpecialize share a body but
    /// not a name: deriving the name from the shape writes every specialize hook
    /// under the forkAndSpecialize prefix, and the table then advertises a
    /// signature the device never calls.
    base: Base,
    /// What the hooked body does.
    body: Body,
}

/// The three shapes of body in this file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Body {
    /// nativeForkAndSpecialize and nativeSpecializeAppProcess: build the args
    /// struct, run the loader around the original, return the child pid.
    ///
    /// The two share a body but not a name, so the base travels separately from
    /// the shape.
    ForkAndSpecialize,
    /// nativeForkSystemServer: the same shape with the server's own args.
    ForkServer,
}

/// The JNI method base name a version is generated for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Base {
    ForkAndSpecialize,
    SpecializeAppProcess,
    ForkSystemServer,
}

impl Base {
    fn name(self) -> &'static str {
        match self {
            Self::ForkAndSpecialize => "nativeForkAndSpecialize",
            Self::SpecializeAppProcess => "nativeSpecializeAppProcess",
            Self::ForkSystemServer => "nativeForkSystemServer",
        }
    }
}

impl Method {
    fn new(version: &str, base: Base, ret: Ret, args: Vec<Arg>) -> Self {
        Self {
            name: format!("{}_{}", base.name(), version),
            ret,
            args,
            base,
            body: match base {
                Base::ForkAndSpecialize | Base::SpecializeAppProcess => Body::ForkAndSpecialize,
                Base::ForkSystemServer => Body::ForkServer,
            },
        }
    }

    /// The C parameter list.
    fn cpp_args(&self) -> String {
        self.args
            .iter()
            .map(Arg::cpp)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Just the names, for the call into the original.
    fn arg_names(&self) -> String {
        self.args
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The JNI descriptor: parameters then return.
    fn descriptor(&self) -> String {
        let params: String = self.args.iter().map(|a| a.type_.descriptor()).collect();

        format!("({}){}", params, self.ret.type_.descriptor())
    }

    fn func_ptr_type(&self) -> String {
        format!("{}_fn", self.base_name())
    }

    fn orig_call(&self) -> String {
        format!("(({}){}_orig)", self.func_ptr_type(), self.base_name())
    }

    fn base_name(&self) -> &'static str {
        self.base.name()
    }

    /// The struct this method fills in before calling the original.
    fn args_struct(&self) -> &'static str {
        match self.body {
            Body::ForkServer => "struct server_specialize_args_v1 args = { .uid = &uid, .gid = &gid, .gids = &gids, .runtime_flags = &runtime_flags, .permitted_capabilities = &permitted_capabilities, .effective_capabilities = &effective_capabilities };",
            Body::ForkAndSpecialize => "struct app_specialize_args_v5 args = { .uid = &uid, .gid = &gid, .gids = &gids, .runtime_flags = &runtime_flags, .rlimits = &rlimits, .mount_external = &mount_external, .se_info = &se_info, .nice_name = &nice_name, .instruction_set = &instruction_set, .app_data_dir = &app_data_dir };",
        }
    }

    fn body(&self) -> String {
        let mut out = String::new();
        let ind = |level: usize| format!("\n{}", "  ".repeat(level));

        out.push_str(&ind(1));
        out.push_str(self.args_struct());

        for arg in &self.args {
            if arg.set_arg {
                out.push_str(&ind(1));
                let _ = write!(out, "args.{0} = &{0};", arg.name);
            }
        }

        out.push_str(&ind(1));
        out.push_str("struct zygisk_context ctx;");
        out.push_str(&ind(1));
        out.push_str("rz_init(&ctx, env, &args);");
        out.push_str(&ind(1));
        let _ = write!(out, "rz_{}_pre(&ctx);", self.base_name());
        out.push_str(&ind(1));
        out.push_str(&self.orig_call());
        out.push('(');
        out.push_str(&ind(2));
        let _ = write!(out, "env, clazz, {}", self.arg_names());
        out.push_str(&ind(1));
        out.push_str(");");
        out.push_str(&ind(1));
        let _ = write!(out, "rz_{}_post(&ctx);", self.base_name());
        out.push_str(&ind(1));
        out.push_str("rz_cleanup(&ctx);");

        out
    }
}

/// Indentation for a nesting level.
fn ind(level: usize) -> String {
    format!("\n{}", "  ".repeat(level))
}

/// One base name's worth of generated declarations: the originals, the hooks
/// and the method table that ties them together.
///
/// The base is taken from the first method rather than passed in, so the three
/// tables cannot disagree about what they are generating.
fn gen_jni_def(methods: &[Method]) -> String {
    let first = &methods[0];
    let func_ptr_type = first.func_ptr_type();

    let mut decl = String::new();

    // The function pointer typedef for the original, taken from the first
    // method's signature: they differ only in argument count.
    decl.push_str(&ind(0));
    let _ = write!(
        decl,
        "typedef {} (*{})(JNIEnv *, jclass, ...);",
        first.ret.type_.cpp(),
        func_ptr_type
    );

    for method in methods {
        decl.push_str(&ind(0));
        let _ = write!(
            decl,
            "__attribute__((no_stack_protector)) static {} {}(JNIEnv *env, jclass clazz, {}) {{",
            method.ret.type_.cpp(),
            method.name,
            method.cpp_args()
        );
        decl.push_str(&method.body());
        if let Some(value) = method.ret.value {
            decl.push_str(&ind(1));
            let _ = write!(decl, "return {value};");
        }
        decl.push_str(&ind(0));
        decl.push('}');
    }

    decl.push_str(&ind(0));
    let _ = write!(
        decl,
        "static JNINativeMethod {}_methods[] = {{",
        first.base_name()
    );
    for method in methods {
        decl.push_str(&ind(1));
        decl.push('{');
        decl.push_str(&ind(2));
        let _ = write!(decl, "\"{}\",", method.base_name());
        decl.push_str(&ind(2));
        let _ = write!(decl, "\"{}\",", method.descriptor());
        decl.push_str(&ind(2));
        let _ = write!(decl, "(void *) &{}", method.name);
        decl.push_str(&ind(1));
        decl.push_str("},");
    }
    decl.push_str(&ind(0));
    decl.push_str("};");

    let mut out = String::new();
    let _ = write!(out, "static void *{}_orig = NULL;", first.base_name());
    out.push_str(&decl);
    // The newline that ends the last line of this table. `DO_HOOK_ZYGOTE` opens
    // with its own, and between two tables the pair leaves the blank line that
    // separates them.
    out.push_str(&ind(0));

    out
}

/// The tail of the header: the one function that installs all three tables.
const DO_HOOK_ZYGOTE: &str = r#"
static void do_hook_zygote(JNIEnv *env) {
  const char *clz = "com/android/internal/os/Zygote";

  JNINativeMethod hooks[3];
  int hooks_count = 0;

  int fork_specialize_methods_count = sizeof(nativeForkAndSpecialize_methods) / sizeof(nativeForkAndSpecialize_methods[0]);
  hook_jni_methods(env, clz, nativeForkAndSpecialize_methods, fork_specialize_methods_count);
  for (int i = 0; i < fork_specialize_methods_count; i++) {
    if (!nativeForkAndSpecialize_methods[i].fnPtr) continue;

    nativeForkAndSpecialize_orig = nativeForkAndSpecialize_methods[i].fnPtr;
    hooks[hooks_count++] = nativeForkAndSpecialize_methods[i];

    break;
  }

  int specialize_methods_count = sizeof(nativeSpecializeAppProcess_methods) / sizeof(nativeSpecializeAppProcess_methods[0]);
  hook_jni_methods(env, clz, nativeSpecializeAppProcess_methods, specialize_methods_count);
  for (int i = 0; i < specialize_methods_count; i++) {
    if (!nativeSpecializeAppProcess_methods[i].fnPtr) continue;

    nativeSpecializeAppProcess_orig = nativeSpecializeAppProcess_methods[i].fnPtr;
    hooks[hooks_count++] = nativeSpecializeAppProcess_methods[i];

    break;
  }

  int server_methods_count = sizeof(nativeForkSystemServer_methods) / sizeof(nativeForkSystemServer_methods[0]);
  hook_jni_methods(env, clz, nativeForkSystemServer_methods, server_methods_count);
  for (int i = 0; i < server_methods_count; i++) {
    if (!nativeForkSystemServer_methods[i].fnPtr) continue;

    nativeForkSystemServer_orig = nativeForkSystemServer_methods[i].fnPtr;
    hooks[hooks_count++] = nativeForkSystemServer_methods[i];

    break;
  }

  jni_hook_list_add(clz, hooks, hooks_count);
}

#endif /* JNI_HOOKS_H */
"#;

/// An argument the hooked body does not copy into the args struct.
fn arg(name: &str, type_: JType) -> Arg {
    Arg::new(name, type_)
}

/// An argument the body does copy: the struct holds pointers, so these are the
/// ones it wires up.
fn arg_set(name: &str, type_: JType) -> Arg {
    Arg::set_arg(name, type_)
}

/// Builds one forkAndSpecialize variant.
///
/// The list is the whole signature, not a tail to be appended to a prefix: every
/// version names the same leading parameters, and spelling them per variant is
/// what keeps the order visible where it is checked.
fn fas(version: &str, args: Vec<Arg>) -> Method {
    Method::new(
        version,
        Base::ForkAndSpecialize,
        ret(Some("ctx.pid"), JType::JInt),
        args,
    )
}

/// Builds one specializeAppProcess variant. Same shape as `fas`.
fn spec(version: &str, args: Vec<Arg>) -> Method {
    Method::new(
        version,
        Base::SpecializeAppProcess,
        ret(None, JType::Void),
        args,
    )
}

fn generate() -> String {
    // The counter is per generation, so the anonymous names restart at _0.
    ANON_COUNT.with(|count| count.set(0));

    let jint_array = || JType::Array(&JType::JInt);

    let fork_and_specialize = vec![
        // fas_l
        fas(
            "l",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
            ],
        ),
        // fas_o
        fas(
            "o",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
            ],
        ),
        // fas_p
        fas(
            "p",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
            ],
        ),
        // fas_q_alt
        fas(
            "q_alt",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
            ],
        ),
        // fas_r
        fas(
            "r",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
            ],
        ),
        // fas_u
        fas(
            "u",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
            ],
        ),
        // fas_c
        fas(
            "c",
            vec![
                arg("uid", JType::JInt),
                Arg::anon(JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                Arg::anon(JType::JBoolean),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
            ],
        ),
        // fas_samsung_m
        fas(
            "samsung_m",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                Arg::anon(JType::JInt),
                Arg::anon(JType::JInt),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
            ],
        ),
        // fas_samsung_n
        fas(
            "samsung_n",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                Arg::anon(JType::JInt),
                Arg::anon(JType::JInt),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                Arg::anon(JType::JInt),
            ],
        ),
        // fas_samsung_o
        fas(
            "samsung_o",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                Arg::anon(JType::JInt),
                Arg::anon(JType::JInt),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
            ],
        ),
        // fas_samsung_p
        fas(
            "samsung_p",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                Arg::anon(JType::JInt),
                Arg::anon(JType::JInt),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
            ],
        ),
        // fas_samsung_b
        fas(
            "samsung_b",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                Arg::anon(JType::JBoolean),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
            ],
        ),
        // fas_grapheneos_u
        fas(
            "grapheneos_u",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
                Arg::anon(JType::Array(&JType::JLong)),
            ],
        ),
        // fas_grapheneos_u_alt
        fas(
            "grapheneos_u_alt",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                Arg::anon(JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
                Arg::anon(JType::Array(&JType::JLong)),
            ],
        ),
        // fas_grapheneos_c
        fas(
            "grapheneos_c",
            vec![
                Arg::anon(JType::Array(&JType::JLong)),
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg("fds_to_close", JType::Array(&JType::JInt)),
                arg_set("fds_to_ignore", JType::Array(&JType::JInt)),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                Arg::anon(JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
            ],
        ),
    ];

    let specialize = vec![
        // spec_q
        spec(
            "q",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
            ],
        ),
        // spec_q_alt
        spec(
            "q_alt",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
            ],
        ),
        // spec_r
        spec(
            "r",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
            ],
        ),
        // spec_u
        spec(
            "u",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
            ],
        ),
        // spec_c
        spec(
            "c",
            vec![
                arg("uid", JType::JInt),
                Arg::anon(JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
            ],
        ),
        // spec_samsung_q
        spec(
            "samsung_q",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                Arg::anon(JType::JInt),
                Arg::anon(JType::JInt),
                arg("nice_name", JType::JString),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
            ],
        ),
        // spec_grapheneos_u
        spec(
            "grapheneos_u",
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
                Arg::anon(JType::Array(&JType::JLong)),
            ],
        ),
        // spec_grapheneos_c
        spec(
            "grapheneos_c",
            vec![
                Arg::anon(JType::Array(&JType::JLong)),
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", JType::Array(&JType::JInt)),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("mount_external", JType::JInt),
                arg("se_info", JType::JString),
                arg("nice_name", JType::JString),
                arg_set("is_child_zygote", JType::JBoolean),
                arg("instruction_set", JType::JString),
                arg("app_data_dir", JType::JString),
                arg_set("is_top_app", JType::JBoolean),
                arg_set("pkg_data_info_list", JType::Array(&JType::JString)),
                arg_set("whitelisted_data_info_list", JType::Array(&JType::JString)),
                arg_set("mount_data_dirs", JType::JBoolean),
                arg_set("mount_storage_dirs", JType::JBoolean),
                arg_set("mount_sysprop_overrides", JType::JBoolean),
            ],
        ),
    ];

    let server = vec![
        Method::new(
            "l",
            Base::ForkSystemServer,
            ret(Some("ctx.pid"), JType::JInt),
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", jint_array()),
                arg("runtime_flags", JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("permitted_capabilities", JType::JLong),
                arg("effective_capabilities", JType::JLong),
            ],
        ),
        Method::new(
            "samsung_q",
            Base::ForkSystemServer,
            ret(Some("ctx.pid"), JType::JInt),
            vec![
                arg("uid", JType::JInt),
                arg("gid", JType::JInt),
                arg("gids", jint_array()),
                arg("runtime_flags", JType::JInt),
                Arg::anon(JType::JInt),
                Arg::anon(JType::JInt),
                arg("rlimits", JType::Array(&JType::Array(&JType::JInt))),
                arg("permitted_capabilities", JType::JLong),
                arg("effective_capabilities", JType::JLong),
            ],
        ),
    ];

    let mut out = String::new();
    out.push_str("/* Generated by gen_jni_hooks.py */\n");
    out.push_str("#ifndef JNI_HOOKS_H\n");
    // Three newlines: the guard line itself, then the blank line the generator
    // this replaced wrote, then the leading newline of the first declaration's
    // indentation. The header is compared byte for byte, so all three are here.
    out.push_str("#define JNI_HOOKS_H\n\n\n");

    // Each table ends with the newline that closes its last line; the blank line
    // between two tables is the one this adds, so that neither `gen_jni_def` nor
    // the tail block has to know whether it is the first or the last.
    out.push_str(&gen_jni_def(&fork_and_specialize));
    out.push('\n');
    out.push_str(&gen_jni_def(&specialize));
    out.push('\n');
    out.push_str(&gen_jni_def(&server));

    out.push_str(DO_HOOK_ZYGOTE);

    out
}

fn main() -> ExitCode {
    let out_path = match std::env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        // The header lands in the loader's injector directory, which is where
        // hook.c includes it from, so the generator can be run from anywhere.
        None => {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../loader/src/injector/jni_hooks.h")
        }
    };

    let header = generate();

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    match std::fs::write(&out_path, header) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cannot write {}: {e}", out_path.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_starts_with_its_guard() {
        let header = generate();
        assert!(header.starts_with(
            "/* Generated by gen_jni_hooks.py */\n#ifndef JNI_HOOKS_H\n#define JNI_HOOKS_H\n\n"
        ));
        assert!(header.trim_end().ends_with("#endif /* JNI_HOOKS_H */"));
    }

    #[test]
    fn every_base_name_gets_an_originals_pointer_and_a_table() {
        let header = generate();

        for base in [
            "nativeForkAndSpecialize",
            "nativeSpecializeAppProcess",
            "nativeForkSystemServer",
        ] {
            assert!(header.contains(&format!("static void *{base}_orig = NULL;")));
            assert!(header.contains(&format!("static JNINativeMethod {base}_methods[] = {{")));
        }

        // The typedef's return type comes from the first method of each table,
        // and specializeAppProcess is the one that returns void.
        for base in ["nativeForkAndSpecialize", "nativeForkSystemServer"] {
            assert!(header.contains(&format!(
                "typedef jint (*{base}_fn)(JNIEnv *, jclass, ...);"
            )));
        }
        assert!(header
            .contains("typedef void (*nativeSpecializeAppProcess_fn)(JNIEnv *, jclass, ...);"));
    }

    #[test]
    fn the_descriptors_match_the_signature() {
        // l is the plain Android 12 signature.
        let method = Method::new(
            "l",
            Base::ForkAndSpecialize,
            ret(Some("ctx.pid"), JType::JInt),
            vec![
                arg("uid", JType::JInt),
                arg("se_info", JType::JString),
                arg("gids", JType::Array(&JType::JInt)),
            ],
        );

        assert_eq!(method.descriptor(), "(ILjava/lang/String;[I)I");
        // jintArray, not jint *: the signature names the type jni.h declares.
        assert_eq!(
            method.cpp_args(),
            "jint uid, jstring se_info, jintArray gids"
        );
    }

    #[test]
    fn an_array_of_a_primitive_has_its_own_c_type() {
        // jni.h declares jintArray and jlongArray, so the signature uses them
        // rather than a pointer; an array of anything else is a jobjectArray.
        assert_eq!(JType::Array(&JType::JInt).cpp(), "jintArray");
        assert_eq!(JType::Array(&JType::JLong).cpp(), "jlongArray");
        assert_eq!(JType::Array(&JType::JBoolean).cpp(), "jbooleanArray");
        assert_eq!(JType::Array(&JType::JString).cpp(), "jobjectArray");
        // Two levels deep is still a jobjectArray.
        assert_eq!(
            JType::Array(&JType::Array(&JType::JInt)).cpp(),
            "jobjectArray"
        );
    }

    #[test]
    fn an_array_descriptor_is_a_bracket_then_the_element() {
        assert_eq!(JType::Array(&JType::JInt).descriptor(), "[I");
        assert_eq!(JType::Array(&JType::JLong).descriptor(), "[J");
        assert_eq!(JType::Array(&JType::JBoolean).descriptor(), "[Z");
        assert_eq!(
            JType::Array(&JType::JString).descriptor(),
            "[Ljava/lang/String;"
        );
    }

    #[test]
    fn the_anonymous_counter_restarts_for_each_generation() {
        // Two runs have to produce the same header, which is what makes the
        // committed one checkable.
        assert_eq!(generate(), generate());
    }

    #[test]
    fn every_generated_hook_calls_the_original_between_pre_and_post() {
        let header = generate();

        // The body shape has to hold for all of them: pre, original, post,
        // cleanup, in that order.
        let pre_count = header.matches("_pre(&ctx);").count();
        let orig_count = header.matches("_orig)(").count();
        let post_count = header.matches("_post(&ctx);").count();
        let cleanup_count = header.matches("rz_cleanup(&ctx);").count();

        assert!(pre_count > 20, "only {pre_count} pre hooks");
        assert_eq!(pre_count, orig_count);
        assert_eq!(pre_count, post_count);
        assert_eq!(pre_count, cleanup_count);
    }

    #[test]
    fn only_the_flag_arguments_are_copied_into_the_args_struct() {
        // fds_to_close is not one of them: a pointer to it would dangle once the
        // original returns, which is why the generator tracks this per argument.
        let header = generate();

        assert!(header.contains("args.fds_to_ignore = &fds_to_ignore;"));
        assert!(header.contains("args.is_child_zygote = &is_child_zygote;"));
        assert!(!header.contains("args.fds_to_close = &fds_to_close;"));
        assert!(!header.contains("args.uid = &uid;"));
    }

    #[test]
    fn the_install_function_names_all_three_tables() {
        let header = generate();

        for base in [
            "nativeForkAndSpecialize",
            "nativeSpecializeAppProcess",
            "nativeForkSystemServer",
        ] {
            assert!(header.contains(&format!("hook_jni_methods(env, clz, {base}_methods,")));
            assert!(header.contains(&format!("{base}_orig = {base}_methods[i].fnPtr;")));
        }

        assert!(header.contains("JNINativeMethod hooks[3];"));
        assert!(header.contains("jni_hook_list_add(clz, hooks, hooks_count);"));
    }

    #[test]
    fn the_server_hook_uses_the_server_args_struct() {
        let header = generate();
        assert!(header.contains("struct server_specialize_args_v1 args = {"));
        assert!(header.contains("struct app_specialize_args_v5 args = {"));
    }
}
