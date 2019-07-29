/*
 * Copyright (c) 2008, 2015, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the Classpath exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.sun.btrace.samples;

import com.sun.btrace.annotations.*;
import static com.sun.btrace.BTraceUtils.*;

@BTrace(unsafe=true)
public class AllCalls {
    private static final String CLAZZ_PATTERN = "/es.*|org.*/";
    private static final String METHOD_PATTERN = "/.*/";

    @OnMethod(
        clazz=CLAZZ_PATTERN, 
        method=METHOD_PATTERN, 
        location=@Location(value=Kind.CALL, clazz=CLAZZ_PATTERN, method=METHOD_PATTERN)
    )
    public static void mc(@Self Object self, @TargetMethodOrField String method, @ProbeClassName String probeClass, @ProbeMethodName String probeMethod) {
        println(timestamp() + " --- CALL " + method + "@" + probeClass + ":" + probeMethod);
    }

    @OnMethod(
        clazz=CLAZZ_PATTERN, 
        method=METHOD_PATTERN, 
        location=@Location(value=Kind.ENTRY)
    )
    public static void me(@Self Object self, @ProbeClassName String probeClass, @ProbeMethodName String probeMethod) {
        println(timestamp() + " ENTRY " + probeClass + ":" + probeMethod);
    }
}
