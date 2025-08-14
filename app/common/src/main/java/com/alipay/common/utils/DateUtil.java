/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alipay.common.utils;

import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class DateUtil {

    public static String YYYY_MM_DD_HH_MM_SS = "yyyy-MM-dd HH:mm:ss";
    public static String YYYY_MM_DD = "yyyy-MM-dd";

    public static String dateToString(Date date) {
        return dateToString(date, YYYY_MM_DD);
    }

    public static String dateToString(Date date, String pattern) {
        SimpleDateFormat formatter = new SimpleDateFormat(pattern);
        return formatter.format(date);
    }

    public static Date plusDay(Date date, int day) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.DAY_OF_MONTH, day);

        return calendar.getTime();
    }

    public static Date stringToDate(String date) {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        formatter.setTimeZone(TimeZone.getDefault());
        try {
            return formatter.parse(date);
        } catch (ParseException e) {
            return null;
        }
    }

    public static Date stringToDate(String date, String pattern) {
        SimpleDateFormat formatter = new SimpleDateFormat(pattern);
        formatter.setTimeZone(TimeZone.getDefault());
        try {
            return formatter.parse(date);
        } catch (ParseException e) {
            return null;
        }
    }

    public static String getDayNumber() {
        LocalDate today = LocalDate.now();
        DayOfWeek dayOfWeek = today.getDayOfWeek();

        return switch (dayOfWeek) {
            case MONDAY -> "1";
            case TUESDAY -> "2";
            case WEDNESDAY -> "3";
            case THURSDAY -> "4";
            case FRIDAY -> "5";
            case SATURDAY -> "6";
            case SUNDAY -> "7";
        };
    }

    public static int getCurrentHour() {
        LocalDateTime now = LocalDateTime.now();
        return now.getHour();
    }

    public static Date getYesterdayEndTime() {
        LocalDateTime yesterdayEnd = LocalDateTime.now().minusDays(1).withHour(23).withMinute(59).withSecond(59)
                .withNano(999999999);
        return Date.from(yesterdayEnd.atZone(ZoneId.systemDefault()).toInstant());
    }

    public static Date getYesterdayStartTime() {
        LocalDateTime yesterdayEnd = LocalDateTime.now().minusDays(1).withHour(0).withMinute(0).withSecond(0)
                .withNano(999999999);
        return Date.from(yesterdayEnd.atZone(ZoneId.systemDefault()).toInstant());
    }

    public static Date getTodayEndTime() {
        LocalDateTime yesterdayEnd = LocalDateTime.now().withHour(23).withMinute(59).withSecond(59)
                .withNano(999999999);
        return Date.from(yesterdayEnd.atZone(ZoneId.systemDefault()).toInstant());
    }

    public static int getDiffHours(Date d1, Date d2) {
        if (d1 == null || d2 == null) {
            return 0;
        }
        return (int) ((d1.getTime() - d2.getTime()) / (1000 * 60 * 60));
    }

    public static String formatISODateTime(String iSODateTime) {
        if (StringUtils.isBlank(iSODateTime)) {
            return null;
        }
        String formattedDate = null;
        try {
            SimpleDateFormat isoFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
            isoFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

            Date date = isoFormat.parse(iSODateTime.replace("Z", ""));
            SimpleDateFormat targetFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            formattedDate = targetFormat.format(date);

            return formattedDate;
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return formattedDate;
    }
}