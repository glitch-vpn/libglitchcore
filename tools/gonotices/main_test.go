package main

import (
	"reflect"
	"strings"
	"testing"
)

const (
	mitText = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.`

	bsd2Text = `Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.`

	bsd3Text = bsd2Text + `
3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software.`

	bsd4Text = bsd2Text + `
3. All advertising materials mentioning features or use of this software
must display the following acknowledgement: This product includes software
developed by the organization.
4. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software.`

	apache11Text = `Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
3. The end-user documentation included with the redistribution, if any, must
include the following acknowledgment: This product includes software
developed by the Apache Software Foundation.
4. The names "Apache" and "Apache Software Foundation" must not be used to
endorse or promote products derived from this software without prior written
permission.`

	zlibText = `This software is provided 'as-is', without any express or implied warranty.
Permission is granted to anyone to use this software for any purpose, subject
to the following restrictions:
1. The origin of this software must not be misrepresented.
2. Altered source versions must be plainly marked as such.
3. The name of the author may not be used to endorse or promote products
derived from this software.`

	apacheText = `Apache License
Version 2.0, January 2004`

	gplv3Text = `GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007
...
either version 3 of the License, or (at your option) any later version.
...
use the GNU Lesser General Public License instead of this License.`

	gplNotice = `This program is free software: you can redistribute it under the terms of
the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.`
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{"mit", mitText, []string{"MIT"}},
		{"bsd2", bsd2Text, []string{"BSD-2-Clause"}},
		{"bsd3 is not also bsd2", bsd3Text, []string{"BSD-3-Clause"}},
		{"mit then bsd3", mitText + "\n\n" + bsd3Text, []string{"MIT", "BSD-3-Clause"}},
		{"bsd3 then mit", bsd3Text + "\n\n" + mitText, []string{"MIT", "BSD-3-Clause"}},
		{"bsd3 and bsd2", bsd3Text + "\n\n" + bsd2Text, []string{"BSD-3-Clause", "BSD-2-Clause"}},
		{"mit, bsd3 and bsd2", mitText + "\n" + bsd3Text + "\n" + bsd2Text, []string{"MIT", "BSD-3-Clause", "BSD-2-Clause"}},
		{"bsd4 is neither bsd3 nor bsd2", bsd4Text, []string{"BSD-4-Clause"}},
		{"apache 1.1 is neither bsd3 nor bsd2", apache11Text, []string{"Apache-1.1"}},
		{"bsd3 and bsd4", bsd3Text + "\n\n" + bsd4Text, []string{"BSD-3-Clause", "BSD-4-Clause"}},
		{"bsd2 and apache 1.1", bsd2Text + "\n\n" + apache11Text, []string{"BSD-2-Clause", "Apache-1.1"}},
		{"an endorsement clause without the redistribution clauses is not bsd", zlibText, nil},
		{"apache and mit", apacheText + "\n" + mitText, []string{"Apache-2.0", "MIT"}},
		{"full gpl text naming the lgpl is gpl only", gplv3Text, []string{"GPL-3.0"}},
		{"short gpl notice", gplNotice, []string{"GPL-3.0-or-later"}},
		{"gpl notice and mit", gplNotice + "\n" + mitText, []string{"GPL-3.0-or-later", "MIT"}},
		{"unrelated text", "Grabbed from somewhere with modifications", nil},
	}
	for _, c := range cases {
		got := classify(c.text)
		if !sameSet(got, c.want) {
			t.Errorf("%s: classify = %v, want %v", c.name, got, c.want)
		}
	}
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	return reflect.DeepEqual(unique(append([]string(nil), got...)), unique(append([]string(nil), want...)))
}

func TestReleaseTargetsTakeTheirTagsFromTheCaller(t *testing.T) {
	targets := releaseTargets("with_gvisor trim", "cmfa", "service", []string{"arm64", "arm"})
	want := map[string]string{
		"android/arm64":         "with_gvisor trim cmfa",
		"android/arm":           "with_gvisor trim cmfa",
		"linux/amd64":           "with_gvisor trim",
		"windows/amd64 dll":     "with_gvisor trim",
		"windows/amd64 service": "service with_gvisor trim",
	}
	if len(targets) != len(want) {
		t.Fatalf("got %d targets, want %d", len(targets), len(want))
	}
	for _, target := range targets {
		if want[target.name] != target.tags {
			t.Errorf("%s: tags %q, want %q", target.name, target.tags, want[target.name])
		}
	}
	if strings.Contains(targets[2].tags, "cmfa") {
		t.Error("cmfa leaked into a non-android target")
	}
}

func TestGuardedModuleMustBeReplacedByItsStub(t *testing.T) {
	cases := []struct {
		name    string
		module  module
		wantErr bool
	}{
		{"an upstream copy of a guarded module fails", module{path: "github.com/rasky/go-lzo"}, true},
		{"a replacement by another directory fails", module{path: "github.com/rasky/go-lzo", replacePath: "../elsewhere"}, true},
		{"a replacement by an upstream fork fails", module{path: "github.com/rasky/go-lzo", replacePath: "github.com/someone/go-lzo", replaceVer: "v1.0.0"}, true},
		{"the stub passes", module{path: "github.com/rasky/go-lzo", replacePath: "./third_party/nolzo"}, false},
		{"a module nobody guards passes", module{path: "github.com/example/other"}, false},
	}
	for _, c := range cases {
		err := checkReplacement(&c.module)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

func TestHeaderNamesOwnCodeInsteadOfListingIt(t *testing.T) {
	stub := &module{path: "github.com/rasky/go-lzo", replacePath: "./third_party/nolzo"}
	if !isOwnCode(stub) {
		t.Fatal("a module replaced by a local directory is not own code")
	}
	for _, upstream := range []*module{{path: "a/b"}, {path: "a/b", replacePath: "github.com/fork/b", replaceVer: "v1.0.0"}} {
		if isOwnCode(upstream) {
			t.Errorf("%+v is own code", upstream)
		}
	}
	got := header(142, []*module{stub})
	want := "Go modules linked by the release binaries: 142.\n" +
		"github.com/rasky/go-lzo is not listed: go.mod replaces it with the core's own module third_party/nolzo.\n" +
		"Generated by `make notices`; do not edit.\n\n"
	if got != want {
		t.Errorf("header =\n%s\nwant\n%s", got, want)
	}
}
