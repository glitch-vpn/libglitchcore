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
