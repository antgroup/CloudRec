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
package com.alipay.application.service.system.utils;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * HttpServletRequestWrapper that caches the request body to allow multiple reads
 * This solves the "getInputStream() has already been called" issue when multiple
 * components need to read the request body
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {
    
    private final byte[] cachedBody;
    
    /**
     * Constructor that caches the request body
     * 
     * @param request the original HTTP servlet request
     * @throws IOException if reading the request body fails
     */
    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        
        // Read and cache the request body
        try (InputStream inputStream = request.getInputStream()) {
            this.cachedBody = inputStream.readAllBytes();
        }
    }
    
    /**
     * Get the cached request body as a string
     * 
     * @return the request body as a UTF-8 string
     */
    public String getBody() {
        return new String(this.cachedBody, StandardCharsets.UTF_8);
    }
    
    /**
     * Override getInputStream to return a new stream from cached body
     * 
     * @return a new ServletInputStream from the cached body
     */
    @Override
    public ServletInputStream getInputStream() {
        return new CachedBodyServletInputStream(this.cachedBody);
    }
    
    /**
     * Override getReader to return a new reader from cached body
     * 
     * @return a new BufferedReader from the cached body
     */
    @Override
    public BufferedReader getReader() {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.cachedBody);
        return new BufferedReader(new InputStreamReader(byteArrayInputStream, StandardCharsets.UTF_8));
    }
    
    /**
     * Custom ServletInputStream implementation that reads from cached body
     */
    private static class CachedBodyServletInputStream extends ServletInputStream {
        
        private final ByteArrayInputStream byteArrayInputStream;
        
        /**
         * Constructor
         * 
         * @param cachedBody the cached request body
         */
        public CachedBodyServletInputStream(byte[] cachedBody) {
            this.byteArrayInputStream = new ByteArrayInputStream(cachedBody);
        }
        
        @Override
        public boolean isFinished() {
            return byteArrayInputStream.available() == 0;
        }
        
        @Override
        public boolean isReady() {
            return true;
        }
        
        @Override
        public void setReadListener(ReadListener readListener) {
            // Not implemented for this use case
            throw new UnsupportedOperationException("ReadListener not supported");
        }
        
        @Override
        public int read() {
            return byteArrayInputStream.read();
        }
        
        @Override
        public int read(byte[] b, int off, int len) {
            return byteArrayInputStream.read(b, off, len);
        }
        
        @Override
        public void close() throws IOException {
            byteArrayInputStream.close();
        }
    }
}