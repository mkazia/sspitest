/*
 * Copyright 2018 Cloudera Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudera.ps.sspitest;

import com.sun.jna.Native;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.Sspi.SecBufferDesc;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.ptr.IntByReference;


public class SspiTest {
    public static void main(String[] args){

        if (args.length < 1) {
            System.err.println("SspiTest <SPN>");
            System.exit (-1);
        }

        CredHandle phCredential = new CredHandle();
        TimeStamp ptsExpiry = new TimeStamp();

        int result = Secur32.INSTANCE.AcquireCredentialsHandle(
                null, "Negotiate", Sspi.SECPKG_CRED_OUTBOUND, null,
                null, null,
                null, phCredential, ptsExpiry);
        if (result != W32Errors.SEC_E_OK) {
            System.err.println(
                    "AcquireCredentialsHandle result="+ result +
                            ", lastErrorCode="+ Native.getLastError());
            return;
        }

        // initialize security context
        Sspi.CtxtHandle phNewContext = new Sspi.CtxtHandle();
        SecBufferDesc pbToken = new SecBufferDesc(Sspi.SECBUFFER_TOKEN,
                Sspi.MAX_TOKEN_SIZE);
        IntByReference pfContextAttr = new IntByReference();

        result = Secur32.INSTANCE.InitializeSecurityContext(
                phCredential,
                null,
                args[0],
                Sspi.ISC_REQ_CONNECTION,
                0,
                Sspi.SECURITY_NATIVE_DREP,
                null,
                0,
                phNewContext,
                pbToken,
                pfContextAttr,
                null);

        if (result != W32Errors.SEC_E_OK &&
                result != W32Errors.SEC_I_CONTINUE_NEEDED) {
            System.err.println(
                    "InitializeSecurityContext result="+ result +"," +
                            " lastErrorCode="+ Native.getLastError());
        }
        if (phNewContext.dwLower != null &&
                phNewContext.dwUpper != null &&
                pbToken.pBuffers[0].getBytes().length > 0) {
            System.err.println("Success!");
        }

        result = Secur32.INSTANCE.DeleteSecurityContext(phNewContext);
        result = Secur32.INSTANCE.FreeCredentialsHandle(phCredential);
    }
}
