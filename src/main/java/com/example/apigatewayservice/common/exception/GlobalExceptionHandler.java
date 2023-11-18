package com.example.apigatewayservice.common.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import org.springframework.http.HttpStatus;

@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler implements ErrorWebExceptionHandler {

    @Autowired
    private ObjectMapper objectMapper;

    private final Logger logger= LoggerFactory.getLogger(GlobalExceptionHandler.class);

    //response body에 에러 내용을 작성해줌.
    @Override
    public Mono<Void> handle(ServerWebExchange serverWebExchange, Throwable throwable) {

        logger.debug("throwable is : {}",throwable.getMessage());

        List<Class<? extends RuntimeException>> jwtExceptions =
                List.of(SignatureException.class,
                        MalformedJwtException.class,
                        UnsupportedJwtException.class,
                        IllegalArgumentException.class,
                        NoAuthorizationHeaderException.class);

        Class<? extends Throwable> exceptionClass = throwable.getClass();

        Map<String, Object> responseBody = new HashMap<>();

        if (exceptionClass == ExpiredJwtException.class) {
            serverWebExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            serverWebExchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            responseBody.put("errorMessage", "access token has expired");

        } else if (jwtExceptions.contains(exceptionClass)) {
            serverWebExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            serverWebExchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            responseBody.put("errorMessage", "invalid access token");
        } else {
            serverWebExchange.getResponse().setStatusCode(serverWebExchange.getResponse().getStatusCode());
            serverWebExchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            responseBody.put("errorMessage", throwable.getMessage());
        }

        DataBuffer wrap = null;
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(responseBody);
            wrap = serverWebExchange.getResponse().bufferFactory().wrap(bytes);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return serverWebExchange.getResponse().writeWith(Flux.just(wrap));
    }
}