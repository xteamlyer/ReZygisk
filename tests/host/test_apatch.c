/* INFO: Host-side tests for the APatch package_config parser in apatch.c.

   The parser is the daemon's view of who gets root and who is denylisted on
   an APatch device, so a quoting regression would quietly hand out or deny
   privileges. The .c is included so the static helpers are reachable; only
   the pure parsing and matching functions are exercised, never the file
   paths. */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "check.h"

#include "../../zygiskd/src/root_impl/apatch.c"

static void check_csv_quoting(void) {
  printf("-- csv field parsing\n");

  /* INFO: RFC 4180: commas inside quotes stay in the field, and a doubled
           quote is a literal quote. */
  const char *line = "\"com.quoted,app\",1,0,10234,10399,u:r:su:s0";
  char fields[6][AP_PKG_NAME_MAX + 1];
  size_t count = ap_parse_csv_line(line, fields, 6);

  CHECK(count == 6, "expected 6 fields, got %zu", count);
  if (count == 6) {
    CHECK(strcmp(fields[0], "com.quoted,app") == 0, "quoted pkg lost its comma: %s", fields[0]);
    CHECK(strcmp(fields[1], "1") == 0, "exclude field wrong: %s", fields[1]);
    CHECK(strcmp(fields[2], "0") == 0, "allow field wrong: %s", fields[2]);
    CHECK(strcmp(fields[3], "10234") == 0, "uid field wrong: %s", fields[3]);
    CHECK(strcmp(fields[5], "u:r:su:s0") == 0, "sctx field wrong: %s", fields[5]);
  }

  /* INFO: An unterminated quote consumes the rest of the line but must not
           read past it. */
  char trailing[6][AP_PKG_NAME_MAX + 1];
  size_t len = ap_parse_csv_line("\"open,quoted,1,2,3", trailing, 6);
  CHECK(len >= 1 && strcmp(trailing[0], "open,quoted,1,2,3") == 0,
        "unterminated quote misparsed (len %zu, field %s)", len, trailing[0]);

  /* INFO: A literal quote inside a quoted field. */
  char doubled[6][AP_PKG_NAME_MAX + 1];
  len = ap_parse_csv_line("\"say \"\"hi\"\"\",0,1,2000,2000,", doubled, 6);
  CHECK(len == 6 && strcmp(doubled[0], "say \"hi\"") == 0,
        "doubled quote misparsed: %s", doubled[0]);
}

static void check_row_matching(void) {
  printf("-- uid matching\n");

  struct ap_package_entry entry = {
    .exclude = false,
    .allow = true,
    .uid = 10100,
  };

  CHECK(ap_row_matches(&entry, 10100), "the row's own uid must match");
  CHECK(!ap_row_matches(&entry, 10099), "a neighbour below must not match");
  CHECK(!ap_row_matches(&entry, 10101), "a neighbour above must not match");
  CHECK(!ap_row_matches(&entry, 10199), "a uid inside the old range must not match");

  /* INFO: A work profile's row carries the user offset in the uid itself, which
           is what keeps two profiles of one app apart. */
  struct ap_package_entry profile = {
    .exclude = true,
    .allow = false,
    .uid = 1010123,
  };

  CHECK(ap_row_matches(&profile, 1010123), "the profile's own uid must match");
  CHECK(!ap_row_matches(&profile, 10123), "the device owner's uid must not match");

  /* INFO: The parsed boolean columns decide which list a row belongs to. */
  CHECK(ap_parse_bool_field("1"), "a one must be true");
  CHECK(!ap_parse_bool_field("0"), "a zero must be false");
}

int main(void) {
  check_csv_quoting();
  check_row_matching();

  if (g_failures == 0) {
    printf("all apatch checks passed\n");

    return 0;
  }

  printf("%d apatch check(s) failed\n", g_failures);

  return 1;
}
