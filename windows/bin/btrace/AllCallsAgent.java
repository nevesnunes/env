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

import com.sun.btrace.AnyType;
import com.sun.btrace.annotations.*;
import static com.sun.btrace.BTraceUtils.*;

@BTrace(unsafe = true)
public class AllCallsAgent {
    //
    // NOTE: clazz pattern _MUST_ have a prefix,
    // otherwise no matches are transformed.
    //
    // private static final String CLAZZ_PATTERN = "/es.*/";
    // private static final String CLAZZ_PATTERN = "/es.*|org.mockito.internal.creation.*|org.mockito.internal.handler.*|org.mockito.internal.stubbing.*/";
    //
    // CSIDE
    // private static final String CLAZZ_PATTERN = "/com.*|freemarker.*|org.*/";
    // private static final String CLAZZ_PATTERN = "/com.opentext.*|freemarker.*|org.antlr.*/";
    private static final String CLAZZ_PATTERN = "/com.opentext.oscript.*|org.antlr.*/";

    private static final String METHOD_PATTERN = "/.*/";

    @OnMethod(
        clazz = CLAZZ_PATTERN,
        method = METHOD_PATTERN,
        location = @Location(value = Kind.CALL, clazz = CLAZZ_PATTERN, method = METHOD_PATTERN)
    )
    // FIXME: java.lang.VerifyError: Instruction type does not match stack map
    // public static void mc(@Self Object self, @TargetMethodOrField String method, @ProbeClassName String probeClass, @ProbeMethodName String probeMethod, AnyType[] args) {
    public static void mc(@Self Object self, @TargetMethodOrField String method, @ProbeClassName String probeClass, @ProbeMethodName String probeMethod) {
        println(timestamp() + " --- CALL " + method + "@" + probeClass + ":" + probeMethod);
    }

    @OnMethod(
        clazz = CLAZZ_PATTERN,
        method = METHOD_PATTERN,
        location = @Location(value = Kind.ENTRY)
    )
    public static void me(@Self Object self, @ProbeClassName String probeClass, @ProbeMethodName String probeMethod) {
        println(timestamp() + " ENTRY " + probeClass + ":" + probeMethod);
    }

    @TLS static Throwable currentException;

    @OnMethod(
        clazz = "+java.lang.Throwable",
        method = "<init>"
    )
    public static void onthrow2(@Self Throwable self, Throwable cause) {
        currentException = self;
    }

    @OnMethod(
        clazz = "java.lang.Throwable",
        method = "<init>",
        location = @Location(Kind.RETURN)
    )
    public static void onthrowreturn() {
        if (currentException != null) {
            Threads.jstack(currentException);
            println(timestamp() + " !!! ERR ");
            currentException = null;
        }
    }

    @OnError
    public static void onerror(Throwable t) {
        println(timestamp() + " !!! ERR ");
        Threads.jstack(t);
    }
}
