package com.example.apigatewayservice;

import com.example.apigatewayservice.common.exception.GlobalExceptionHandler;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.trace.http.HttpTraceRepository;
import org.springframework.boot.actuate.trace.http.InMemoryHttpTraceRepository;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class ApigatewayServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApigatewayServiceApplication.class, args);
	}

	@Bean
	public HttpTraceRepository httpTraceRepository(){
		return new InMemoryHttpTraceRepository();
	}

	@Bean
	public ErrorWebExceptionHandler globalExceptionHandler(){
		return new GlobalExceptionHandler();
	}
}
