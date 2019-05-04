package com.demkada.guard.server.commons.model;

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


import com.datastax.driver.core.ConsistencyLevel;
import com.demkada.guard.server.commons.utils.Constant;
import info.archinnov.achilles.annotations.*;

import java.util.HashMap;
import java.util.Map;

@Table(table= Constant.USERS_BY_EMAIL)
@Consistency(
        read = ConsistencyLevel.LOCAL_QUORUM,
        write = ConsistencyLevel.LOCAL_QUORUM,
        serial = ConsistencyLevel.LOCAL_SERIAL)
public class User {

    @Column(Constant.EMAIL)
    @PartitionKey
    private String email;

    @Column(Constant.SUB)
    private String sub;

    @Column(Constant.GIVEN_NAME)
    private String givenName;

    @Column(Constant.FAMILY_NAME)
    private String familyName;

    @Column(Constant.EMAIL_VERIFIED)
    private boolean emailVerified;

    @Column(Constant.ADDRESS)
    private String address;

    @Column(Constant.PHONE_NUMBER)
    private String phoneNumber;

    @Column(Constant.PHONE_NUMBER_VERIFIED)
    private boolean phoneNumberVerified;

    @Column(Constant.ID_ORIGIN)
    private String idOrigin;

    @Column(Constant.DISABLE)
    private boolean disable;

    @Column(Constant.PASS)
    private String pwd;

    @Column(Constant.ADVANCED_ATTR)
    private Map<String, String> advancedAttributes = new HashMap<>();

    @Column(Constant.PIN)
    private String pin;

    @Column(Constant.SECURITY_QUESTION)
    private Map<@Enumerated(Enumerated.Encoding.ORDINAL) QuestionId , String> securityQuestion = new HashMap<>();

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPwd() {
        return pwd;
    }

    public void setPwd(String pwd) {
        this.pwd = pwd;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getGivenName() {
        return givenName;
    }

    public Map<QuestionId, String> getSecurityQuestion() {
        return securityQuestion;
    }

    public void setSecurityQuestion(Map<QuestionId, String> securityQuestion) {
        this.securityQuestion = securityQuestion;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public boolean isPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public void setPhoneNumberVerified(boolean phoneNumberVerified) {
        this.phoneNumberVerified = phoneNumberVerified;
    }

    public String getIdOrigin() {
        return idOrigin;
    }

    public void setIdOrigin(String idOrigin) {
        this.idOrigin = idOrigin;
    }

    public boolean isDisable() {
        return disable;
    }

    public void setDisable(boolean disable) {
        this.disable = disable;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public Map<String, String> getAdvancedAttributes() {
        return advancedAttributes;
    }

    public void setAdvancedAttributes(Map<String, String> advancedAttributes) {
        this.advancedAttributes = advancedAttributes;
    }
}
