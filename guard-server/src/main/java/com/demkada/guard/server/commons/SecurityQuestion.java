package com.demkada.guard.server.commons;

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


import com.demkada.guard.server.commons.model.QuestionId;

import java.util.EnumMap;
import java.util.Map;

public class SecurityQuestion {

    private Map<QuestionId, String> englishQuestions = new EnumMap<>(QuestionId.class);
    private Map<QuestionId, String> frenchQuestions = new EnumMap<>(QuestionId.class);

    public SecurityQuestion() {
        initEnglishQuestions();
        initFrenchQuestions();
    }

    private void initEnglishQuestions() {
        englishQuestions.put(QuestionId.PRIMARY_SCHOOL, "What was the name of your elementary / primary school?");
        englishQuestions.put(QuestionId.HOSPITAL, "What's the name of the hospital in which you were born?");
        englishQuestions.put(QuestionId.PET, "What's the name of your first pet?");
        englishQuestions.put(QuestionId.NEAREST_SIBLING, "In what city or town does your nearest sibling live?");
        englishQuestions.put(QuestionId.CHILDHOOD_FRIEND, "What is your childhood best friend's first name?");
    }
    private void initFrenchQuestions() {
        frenchQuestions.put(QuestionId.PRIMARY_SCHOOL, "Quel est le nom de votre école maternelle / primaire ?");
        frenchQuestions.put(QuestionId.HOSPITAL, "Quel est le nom de l'hôpital dans lequel vous êtes né(e) ?");
        frenchQuestions.put(QuestionId.PET, "Quel est le nom de votre premier animal de compagnie ?");
        frenchQuestions.put(QuestionId.NEAREST_SIBLING, "Dans quel ville habite votre plus proche frère ou soeur ?");
        frenchQuestions.put(QuestionId.CHILDHOOD_FRIEND, "Quel est le prénom de votre meilleur(e) ami(e) d'enfance");
    }

    public Map<QuestionId, String> getEnglishQuestions() {
        return englishQuestions;
    }

    public Map<QuestionId, String> getFrenchQuestions() {
        return frenchQuestions;
    }
}
