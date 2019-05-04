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


import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.rolling.RollingFileAppender;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

import java.util.Objects;

public class GuardAppender extends RollingFileAppender {

    private AWSLogs awsLogs;
    private String nextToken = null;
    private final String guardLogGroup = Constant.GUARD + "-" + System.getenv("GUARD_ENV");

    public GuardAppender() {
        if (Constant.CLOUDWATCH.equalsIgnoreCase(System.getenv(Constant.GUARD_LOG_TARGET))) {
            awsLogs = AWSLogsClientBuilder.standard().build();
            if (Objects.isNull(findLogGroup(guardLogGroup))) {
                awsLogs.createLogGroup(new CreateLogGroupRequest(guardLogGroup));
            }
        }
    }

    @Override
    protected void subAppend(Object event) {
        if (Constant.CLOUDWATCH.equalsIgnoreCase(System.getenv(Constant.GUARD_LOG_TARGET))) {
            @SuppressWarnings("unchecked") JsonObject map = new JsonObject(Buffer.buffer(this.encoder.encode(event)));
            PutLogEventsRequest logEventReq = new PutLogEventsRequest().withLogGroupName(guardLogGroup);
            String streamName = map.getString("source");
            LogStream stream = findLogStream(guardLogGroup, streamName);
            if(Objects.isNull(stream)) {
                awsLogs.createLogStream(new CreateLogStreamRequest(guardLogGroup, streamName));
            }
            else {
                nextToken = stream.getUploadSequenceToken();
            }
            logEventReq.withLogStreamName(streamName);
            nextToken = awsLogs.putLogEvents(
                    logEventReq
                            .withSequenceToken(nextToken)
                            .withLogEvents(new InputLogEvent()
                                    .withTimestamp(((ILoggingEvent) event).getTimeStamp())
                                    .withMessage(JsonObject.mapFrom(map).encode()))
            ).getNextSequenceToken();
        }
        else {
            //noinspection unchecked
           super.subAppend(event);
        }
    }

    private LogGroup findLogGroup(String name) {
        DescribeLogGroupsResult result = awsLogs.describeLogGroups(
                new DescribeLogGroupsRequest()
                        .withLogGroupNamePrefix(name)
        );
        for (LogGroup group : result.getLogGroups()) {
            if (group.getLogGroupName().equals(name)) {
                return group;
            }
        }
        return null;
    }

    private LogStream findLogStream(String groupName, String streamName) {
        DescribeLogStreamsResult result = awsLogs.describeLogStreams(
                new DescribeLogStreamsRequest(groupName)
                        .withLogStreamNamePrefix(streamName)
        );
        for (LogStream stream : result.getLogStreams()) {
            if (stream.getLogStreamName().equals(streamName)) {
                return stream;
            }
        }
        return null;
    }
}
