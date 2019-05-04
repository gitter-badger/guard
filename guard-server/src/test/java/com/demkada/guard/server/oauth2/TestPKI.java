package com.demkada.guard.server.oauth2;

/*
 * Copyright 2019 DEMKADA.
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
 *
 * @author <a href="mailto:kad@demkada.com">Kad D.</a>
*/


public class TestPKI {

    final static String CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIICwDCCAaigAwIBAgIEHg+w2TANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDApJ\n" +
            "bnRlcm1lZENBMB4XDTE5MDQyNjEzNDYzNloXDTI1MTIzMTAwMDAwMFowEDEOMAwG\n" +
            "A1UEAwwFR3VhcmQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCt2b+z\n" +
            "WvUfCGxzhMZPaQbdnVjfDwOv9HzTTinBSiWyv72Exep6ZAEgfe/2BXKJUPYMZciU\n" +
            "0Ct+FTPL8qWEp5gaRhrpH/jioZGte1tB1k+wwOJd/ipvsewihywdjBWOhazhwR9a\n" +
            "jU1Dw0uy8/+P51yTr4t6I6x/QcmZkY72ah++un0CUzlf+9ju/DL+n64ZgDmmrrEb\n" +
            "KqQ0i6joMNR7gaWJEeBRt6IenI8P87XV8rOB7nA+NRWYweX1d6o573QdnzntwTq6\n" +
            "dLhMoQKGTKC1VVeAesDlNxOU4k3cksk1v4rBU7D2YML0RQ0Z4yiaveLxZl/My97k\n" +
            "oPwLDST5zqvT1Pq9AgMBAAGjHTAbMA4GA1UdDwEB/wQEAwIHgDAJBgNVHRMEAjAA\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQBt4jZBcLGOusOBGIp/H8bEn5J4tchjJLvbpyet\n" +
            "s6TDuCstwhEcn+HY/iYdGyGT17U4Em4vPBIOtuAaPFjsTRoJVcjPCxepseTtEufO\n" +
            "OuQKei9lvXtrVkp9S6qqszCk5RIsVURePUwRdVtQElU3heIC4PWsPmNfJFEZR9Ge\n" +
            "fN+nB0z5ZKFk3ceeuE//WWDAiqkXqAm604Emmg2/ViPtmD9PZC9RnyTyOvsud00F\n" +
            "wMNMBARgt7fDVFyn0volK4wRY+xKuFv+yaTNOcHrSlFY5DvZ0vy+hP0AvodW3Lse\n" +
            "wv68dbPQLxjONGih6hdKQMZTI3G5rFSB5LFxxGuB4zIP5Sv/\n" +
            "-----END CERTIFICATE-----\n";

    final static String INTERMEDIATE_CA = "-----BEGIN CERTIFICATE-----\n" +
            "MIICxDCCAaygAwIBAgIE2CvrTDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZy\n" +
            "b290Q0EwHhcNMTkwNDI2MTM0NjM2WhcNMjUxMjMxMDAwMDAwWjAVMRMwEQYDVQQD\n" +
            "DApJbnRlcm1lZENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsh3g\n" +
            "t3yv6lJ/R68XrNYPn7L4OCGqng7aH7TN+OTOH65Nm+xP4uTeKRE0HGLJQCeOegDB\n" +
            "CkWACOM53hqAe8zq6rIzdJyqzJxAxjC4bRJkKiRrsX1As7602QhIRcz0ciwj5x4K\n" +
            "i6PEx23KeLcn2RtRxF/iAgVNqc0nZ/ukxXGjO6Pt9gJMgN1vZNlHn7umginN9WFG\n" +
            "peRPgzW2lAkZ2ssl2zv3EaJ8zg4XIhvhjPN+cPSFD85K3mSFiiDJWyeoMXIAtzE/\n" +
            "hvA/qxDjkU3GoC2AMTHF52EiMTSqngoW6TeG2FAH4SYYZMPp/VSObpO6uOwd0842\n" +
            "KmojREPL46R6gEYIFQIDAQABoyAwHjAOBgNVHQ8BAf8EBAMCAgQwDAYDVR0TBAUw\n" +
            "AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZEjjBntpiXejS+Ler+/QbGEPxOI5dkFG\n" +
            "1mGSX/Mcqe/2lc55OCvO+jov5FDX9pTBeW2TZ58V83Br+ZdBIL7k73UBKHzUiSvf\n" +
            "UXj588JwFxLBUY5jnGDQl1QRrcjpmVZTe98Giw552e2FDXhQMkCBvNXHRrvpyy6e\n" +
            "L/n71YBoIfW0JJbAlT1PIhEG0wyueFL+/S+oB5Dgqf35b81Y8jTd4mpILsCldC1w\n" +
            "7rYBGffmDN+RF3PcNBYIqwZL7foneiHjZ4TNFJVghvW6w82F/KpRhK37iK1n8oUR\n" +
            "apRcSb30CV5wX3xhO7T0/eDDXKoPIQkjFtFDwO29VU7JkVrWJTpxsQ==\n" +
            "-----END CERTIFICATE-----\n";

    final static String ROOT_CA = "-----BEGIN CERTIFICATE-----\n" +
            "MIICwDCCAaigAwIBAgIEsouA7TANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZy\n" +
            "b290Q0EwHhcNMTkwNDI2MTM0NjM2WhcNMjUxMjMxMDAwMDAwWjARMQ8wDQYDVQQD\n" +
            "DAZyb290Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCarLxdcDhp\n" +
            "qkPqF/sY/aUSUxGU+lO5H3t3uDuyhyF6NDdeNdVRM8mH57RPJay6oZy4ql7bQTAW\n" +
            "A3vxep1RAhmLZGTDCS8LaIiYSIuE1w2UMh9RnITyuVNgSIlfZoK6gsL6wRy5qUyH\n" +
            "cO2DlCPXtbItWqu4MnFYYHCrX1tat1+Gb4lNMtqjWvUWs4MOkZ/l6ioBI9Wj5+S/\n" +
            "VPgIBziJylPP4eIiehamIAAjMSczvmB9du2mKDs5Pst76jzkqtkOxSmhNC3OXxFX\n" +
            "g6E+ryo42pqlWbY0emqVnSqau6qhr17wtRiOubHKzqM7ijA5E3a3+DeHRfV33tVN\n" +
            "i7qOvx2Tcl07AgMBAAGjIDAeMA4GA1UdDwEB/wQEAwICBDAMBgNVHRMEBTADAQH/\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQBvWsvz2EaZKhrMJpwsnQn3KN9a/dqpdFmNLGsd\n" +
            "U0rJH8V8WmXHX/LaWZzUc/TWYJTqJ6opBEmIxI+k2qcuiVYep1ARr54C/edBwHnP\n" +
            "zHOttD7tpXrarX2uS1yHbLJWeM4AXJvayrFfjW6jm/p34VQXXqBDcPdlyHt81Kor\n" +
            "vfcK4Aasdfvy1VfDigDYy96hoAn99iqXogVPTkg0dxkMt4gzHTkupboA89hDsUXn\n" +
            "hk84Jn2Buq95haP1vNTmqayYwA0kgOXcBxgmkZVajpNlolpNRUOf4ypk1U9y/XFI\n" +
            "0Jmp0Sh28ESiPQungwQFoVeeMqAxXQFZqZprSIYpBR9uwyTf\n" +
            "-----END CERTIFICATE-----\n";

}
