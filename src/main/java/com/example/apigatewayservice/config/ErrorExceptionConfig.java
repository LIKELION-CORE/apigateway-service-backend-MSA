package com.example.apigatewayservice.config;

import com.example.apigatewayservice.common.exception.GlobalExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

//@Configuration
//@RequiredArgsConstructor
//public class ErrorExceptionConfig {
//    private final ObjectMapper objectMapper;
//    @Bean
//    public ErrorWebExceptionHandler globalExceptionHandler() {
//        return new GlobalExceptionHandler(objectMapper);
//    }
//}
