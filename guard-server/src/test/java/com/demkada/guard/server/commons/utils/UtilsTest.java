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


import org.junit.Assert;
import org.junit.Test;

public class UtilsTest {

    @Test
    public void shouldTestEmptyString(){
        Assert.assertTrue(Utils.isStrEmpty(null));
        Assert.assertTrue(Utils.isStrEmpty(""));

        Assert.assertFalse(Utils.isStrEmpty("notempty"));
    }

    @Test
    public void shouldTestNotEmptyString(){
        Assert.assertFalse(Utils.isStrNotEmpty(null));
        Assert.assertFalse(Utils.isStrNotEmpty(""));

        Assert.assertTrue(Utils.isStrNotEmpty("notempty"));
    }

    @Test
    public void shouldTestEnumValid(){
        Assert.assertFalse(Utils.isEnumValid(EnumForTest.class, null));
        Assert.assertFalse(Utils.isEnumValid(EnumForTest.class, ""));
        Assert.assertFalse(Utils.isEnumValid(EnumForTest.class, "badvalue"));

        Assert.assertTrue(Utils.isEnumValid(EnumForTest.class, "a"));
        Assert.assertTrue(Utils.isEnumValid(EnumForTest.class, "b"));
        Assert.assertTrue(Utils.isEnumValid(EnumForTest.class, "c"));
    }

    private enum EnumForTest{
        a, b, c
    }

}
