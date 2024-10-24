package base

import (
	"testing"
)

func TestConfigAllowlistRegexes(t *testing.T) {
	tests := map[string]struct {
		invalid []string
		valid   []string
	}{
		"general placeholders": {
			invalid: []string{
				`true`, `True`, `false`, `False`, `null`, `NULL`,
			},
		},
		"general placeholders - repeated characters": {
			invalid: []string{
				`aaaaaaaaaaaaaaaaa`, `BBBBBBBBBBbBBBBBBBbBB`, `********************`,
			},
			valid: []string{`aaaaaaaaaaaaaaaaaaabaa`, `pas*************d`},
		},
		"environment variables": {
			invalid: []string{`$2`, `$GIT_PASSWORD`, `${GIT_PASSWORD}`, `$password`},
			valid:   []string{`$yP@R.@=ibxI`, `$2a6WCust9aE`, `${not_complete1`},
		},
		"interpolated variables - ansible": {
			invalid: []string{
				`{{ x }}`, `{{ password }}`, `{{password}}`, `{{ data.proxy_password }}`,
				`{{ dict1 | ansible.builtin.combine(dict2) }}`,
			},
		},
		"interpolated variables - github actions": {
			invalid: []string{
				`${{ env.First_Name }}`,
				`${{ env.DAY_OF_WEEK == 'Monday' }}`,
				`${{env.JAVA_VERSION}}`,
				`${{ github.event.issue.title }}`,
				`${{ github.repository == "Gattocrucco/lsqfitgp" }}`,
				`${{ github.event.pull_request.number || github.ref }}`,
				`${{ github.event_name == 'pull_request' && github.event.action == 'unassigned' }}`,
				`${{ secrets.SuperSecret }}`,
				`${{ vars.JOB_NAME }}`,
				`${{ vars.USE_VARIABLES == 'true' }}`,
			},
		},
		"interpolated variables - nuget": {
			invalid: []string{
				`%MY_PASSWORD%`, `%password%`,
			},
		},
		"interpolated variables - string fmt - golang": {
			invalid: []string{
				`%b`, `%c`, `%d`, `% d`, `%e`, `%E`, `%f`, `%F`, `%g`, `%G`, `%o`, `%O`, `%p`, `%q`, `%-s`, `%s`, `%t`, `%T`, `%U`, `%#U`, `%+v`, `%#v`, `%v`, `%x`, `%X`,
			},
		},
		"interpolated variables - string fmt - python": {
			invalid: []string{
				`{}`, `{0}`, `{10}`,
			},
		},
		"interpolated variables - ucd": {
			invalid: []string{`@password@`, `@LDAP_PASS@`},
			valid:   []string{`@username@mastodon.example`},
		},
	}

	cfg := CreateGlobalConfig()
	allowlist := cfg.Allowlist
	for name, cases := range tests {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases.invalid {
				if !allowlist.RegexAllowed(c) {
					t.Errorf("invalid value not marked as allowed: %s", c)
				}
			}

			for _, c := range cases.valid {
				if allowlist.RegexAllowed(c) {
					t.Errorf("valid value marked as allowed: %s", c)
				}
			}
		})
	}
}

func TestConfigAllowlistPaths(t *testing.T) {
	tests := map[string]struct {
		invalid []string
		valid   []string
	}{
		"javascript - jquery.js": {
			invalid: []string{
				`src/main/resources/static/jquery-ui-1.12.1/jquery-ui-min.js`,
				`src/main/resources/static/js/jquery-ui-1.10.4.min.js`,
			},
		},
		"python": {
			invalid: []string{
				// lock files
				`Pipfile.lock`, `poetry.lock`,
				// virtual environments
				"env/lib/python3.7/site-packages/urllib3/util/url.py",
				"venv/Lib/site-packages/regex-2018.08.29.dist-info/DESCRIPTION.rst",
				"venv/lib64/python3.5/site-packages/pynvml.py",
				"python/python3/virtualenv/Lib/site-packages/pyphonetics/utils.py",
				"virtualenv/lib64/python3.7/base64.py",
				// packages
				"cde-root/usr/lib64/python2.4/site-packages/Numeric.pth",
				"lib/python3.9/site-packages/setuptools/_distutils/msvccompiler.py",
				"lib/python3.8/site-packages/botocore/data/alexaforbusiness/2017-11-09/service-2.json",
				"code/python/3.7.4/Lib/site-packages/dask/bytes/tests/test_bytes_utils.py",
				"python/3.7.4/Lib/site-packages/fsspec/utils.py",
				"python/2.7.16.32/Lib/bsddb/test/test_dbenv.py",
				"python/lib/python3.8/site-packages/boto3/data/ec2/2016-04-01/resources-1.json",
				// distinfo
				"libs/PyX-0.15.dist-info/AUTHORS",
			},
		},
	}

	cfg := CreateGlobalConfig()
	allowlist := cfg.Allowlist
	for name, cases := range tests {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases.invalid {
				if !allowlist.PathAllowed(c) {
					t.Errorf("invalid path not marked as allowed: %s", c)
				}
			}

			for _, c := range cases.valid {
				if allowlist.PathAllowed(c) {
					t.Errorf("valid path marked as allowed: %s", c)
				}
			}
		})
	}
}
