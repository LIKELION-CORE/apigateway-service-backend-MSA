package com.example.apigatewayservice.common.exception;

public class NoAuthorizationHeaderException extends RuntimeException{

    public NoAuthorizationHeaderException(String message) {
        super(message);
    }

    public NoAuthorizationHeaderException(String message, Throwable cause) {
        super(message, cause);
    }
}
