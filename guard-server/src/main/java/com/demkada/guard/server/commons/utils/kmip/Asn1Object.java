package com.demkada.guard.server.commons.utils.kmip;

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


import java.io.IOException;
import java.math.BigInteger;

public class Asn1Object {

    protected final int type;
    protected final int length;
    protected final byte[] value;
    protected final int tag;

    public Asn1Object(int tag, int length, byte[] value) {
        this.tag = tag;
        this.type = tag & 0x1F;
        this.length = length;
        this.value = value;
    }

    public int getType() {
        return type;
    }

    public int getLength() {
        return length;
    }

    public byte[] getValue() {
        return value;
    }

    public boolean isConstructed() {
        return  (tag & DerParser.CONSTRUCTED) == DerParser.CONSTRUCTED;
    }

    public DerParser getParser() throws IOException {
        if (!isConstructed())
            throw new IOException("Invalid DER: can't parse primitive entity"); //$NON-NLS-1$

        return new DerParser(value);
    }

    public BigInteger getInteger() throws IOException {
        if (type != DerParser.INTEGER)
            throw new IOException("Invalid DER: object is not integer"); //$NON-NLS-1$

        return new BigInteger(value);
    }

    public String getString() throws IOException {

        String encoding;

        switch (type) {

            // Not all are Latin-1 but it's the closest thing
            case DerParser.NUMERIC_STRING:
            case DerParser.PRINTABLE_STRING:
            case DerParser.VIDEOTEX_STRING:
            case DerParser.IA5_STRING:
            case DerParser.GRAPHIC_STRING:
            case DerParser.ISO646_STRING:
            case DerParser.GENERAL_STRING:
                encoding = "ISO-8859-1"; //$NON-NLS-1$
                break;

            case DerParser.BMP_STRING:
                encoding = "UTF-16BE"; //$NON-NLS-1$
                break;

            case DerParser.UTF8_STRING:
                encoding = "UTF-8"; //$NON-NLS-1$
                break;

            case DerParser.UNIVERSAL_STRING:
                throw new IOException("Invalid DER: can't handle UCS-4 string"); //$NON-NLS-1$

            default:
                throw new IOException("Invalid DER: object is not a string"); //$NON-NLS-1$
        }

        return new String(value, encoding);
    }
}