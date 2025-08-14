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

import java.util.List;

/*
 *@title ListUtils
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/9/6 15:56
 */
public class ListUtils {

    public static <T> List<T> setList(List<List<T>> list) {
        if (list == null || list.isEmpty()) {
            return null;
        }
        return list.stream().map(e -> {
            if (e.isEmpty()) {
                return null;
            }
            if (e.size() == 1) {
                return e.get(0);
            } else {
                return e.get(1);
            }
        }).toList();
    }

    public static boolean isEmpty(List<?> list) {
        if (list == null || list.isEmpty()) {
            return true;
        }

        // [[]]
        for (Object o : list) {
            if (o == null || (o instanceof List &&((List<?>) o).isEmpty())) {
                return true;
            }
        }

        return false;
    }
    public static boolean isNotEmpty(List<?> list) {
        return !isEmpty(list);
    }

    /**
     * Perform memory-based pagination on a list
     * 
     * @param list the source list to paginate
     * @param page the page number (1-based), defaults to 1 if null
     * @param size the page size, defaults to 10 if null
     * @param <T> the type of list elements
     * @return PaginationResult containing the paginated data and metadata
     */
    public static <T> PaginationResult<T> paginate(List<T> list, Integer page, Integer size) {
        if (list == null) {
            return new PaginationResult<>(List.of(), 0, 1, 10, 0, 0);
        }

        int total = list.size();
        int currentPage = page != null ? page : 1;
        int pageSize = size != null ? size : 10;
        
        // Ensure page is at least 1
        currentPage = Math.max(1, currentPage);
        
        int startIndex = (currentPage - 1) * pageSize;
        int endIndex = Math.min(startIndex + pageSize, total);
        
        List<T> pagedData;
        if (startIndex >= total) {
            pagedData = List.of();
        } else {
            pagedData = list.subList(startIndex, endIndex);
        }
        
        return new PaginationResult<>(pagedData, total, currentPage, pageSize, startIndex, endIndex);
    }

    /**
     * Result class for pagination operations
     * 
     * @param <T> the type of paginated data
     */
    public static class PaginationResult<T> {
        private final List<T> data;
        private final int total;
        private final int page;
        private final int size;
        private final int startIndex;
        private final int endIndex;

        public PaginationResult(List<T> data, int total, int page, int size, int startIndex, int endIndex) {
            this.data = data;
            this.total = total;
            this.page = page;
            this.size = size;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }

        public List<T> getData() {
            return data;
        }

        public int getTotal() {
            return total;
        }

        public int getPage() {
            return page;
        }

        public int getSize() {
            return size;
        }

        public int getStartIndex() {
            return startIndex;
        }

        public int getEndIndex() {
            return endIndex;
        }
    }
}
