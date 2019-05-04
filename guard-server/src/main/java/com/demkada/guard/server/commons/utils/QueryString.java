package com.demkada.guard.server.commons.utils;

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


import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class QueryString {

    private String query = "";

    public QueryString(String name, String value) {
        encode(name, value);
    }

    public QueryString() {
        //Default constructor
    }

    public void add(String name, String value) {
        if (!query.isEmpty()) {
            query += "&";
        }
        encode(name, value);
    }

    private void encode(String name, String value) {
        try {
            query +=URLEncoder.encode(name, "UTF-8");
            query += "=";
            query += URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException("Broken VM does not support UTF-8");
        }
    }

    public String getQuery() {
        return query;
    }

    public String toString() {
        return getQuery();
    }
}
