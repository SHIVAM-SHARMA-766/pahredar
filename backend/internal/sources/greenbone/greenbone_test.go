package greenbone

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

const sample = `# SPDX-License-Identifier: GPL-2.0-only
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117827");
  script_version("2026-10-30T05:05:34+0000");
  script_cve_id("CVE-2021-44228", "CVE-2021-45046");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2026-10-30 05:05:34 +0000 (Fri, 30 Oct 2026)");
  script_name("Apache Log4j RCE Vulnerability (Log4Shell) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_tag(name:"summary", value:"Apache Log4j is prone to a remote code
  execution vulnerability.");
  script_tag(name:"solution", value:"Update to version 2.17.0 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");
  exit(0);
}
`

func TestParse(t *testing.T) {
	got, ok := Parse("2021/apache/gb_log4j.nasl", sample)
	if !ok || got.OID != "1.3.6.1.4.1.25623.1.0.117827" || strings.Join(got.CVEIDs, ",") != "CVE-2021-44228,CVE-2021-45046" {
		t.Fatalf("test = %+v", got)
	}
	if got.Check != "remote" || got.Family != "Web application abuses" || got.Summary != "Apache Log4j is prone to a remote code execution vulnerability." || got.Modified != "2026-10-30" {
		t.Fatalf("fields = %+v", got)
	}
	local := strings.Replace(strings.Replace(sample, "remote_active", "package", 1), "Web application abuses", "Debian Local Security Checks", 1)
	if got, _ := Parse("x.nasl", local); got.Check != "authenticated" {
		t.Fatalf("check = %q", got.Check)
	}
	if _, ok := Parse("x.nasl", strings.Replace(sample, `exit(0);`, `script_tag(name:"deprecated", value:TRUE);`, 1)); ok {
		t.Fatal("deprecated test kept")
	}
	if _, ok := Parse("x.nasl", strings.Replace(sample, `script_cve_id("CVE-2021-44228", "CVE-2021-45046");`, "", 1)); ok {
		t.Fatal("test without a CVE kept")
	}
}

func TestParseLayerKeepsNewestVersion(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	add("var/lib/openvas/22.04/vt-data/nasl/2021/old.nasl", sample)
	add("var/lib/openvas/25.0/vt-data/nasl/2021/new.nasl", sample)
	add("var/lib/openvas/25.0/vt-data/nasl/2021/README", "x")
	tw.Close()
	tests, err := ParseLayer(&buf)
	if err != nil || len(tests) != 1 || tests[0].Path != "2021/new.nasl" {
		t.Fatalf("tests = %+v, err = %v", tests, err)
	}
	if !newerVersion("25.0", "24.10") || newerVersion("22.04", "25.0") {
		t.Fatal("version order")
	}
}
