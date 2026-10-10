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

import com.alibaba.excel.EasyExcel;
import com.alibaba.excel.annotation.ExcelProperty;
import org.apache.poi.ss.SpreadsheetVersion;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExcelExportCompatibilityTest {
    @Test
    void writesNewWorkbookWithUnicodeAndExistingLongCellSupport() throws Exception {
        int original = SpreadsheetVersion.EXCEL2007.getMaxTextLength();
        try {
            ExcelUtils.resetCellMaxTextLength();
            assertEquals(Integer.MAX_VALUE, SpreadsheetVersion.EXCEL2007.getMaxTextLength());
            String text = "风险".repeat(20000);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (var writer = EasyExcel.write(output, ExportRow.class).build()) {
                writer.write(List.of(new ExportRow(text)), EasyExcel.writerSheet("risk").build());
            }
            try (var workbook = new XSSFWorkbook(new ByteArrayInputStream(output.toByteArray()))) {
                assertEquals("Description", workbook.getSheetAt(0).getRow(0).getCell(0).getStringCellValue());
                assertEquals(text, workbook.getSheetAt(0).getRow(1).getCell(0).getStringCellValue());
            }
        } finally {
            Field limit = SpreadsheetVersion.class.getDeclaredField("_maxTextLength");
            limit.setAccessible(true);
            limit.set(SpreadsheetVersion.EXCEL2007, original);
        }
    }

    public static class ExportRow {
        @ExcelProperty("Description")
        private String description;
        public ExportRow() { }
        ExportRow(String description) { this.description = description; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }
}
