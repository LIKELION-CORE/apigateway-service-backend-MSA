package com.example.apigatewayservice.Filter;



import com.example.apigatewayservice.util.JwtProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;


@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    Environment env;
    @Autowired
    private JwtProvider jwtProvider;



    public AuthorizationHeaderFilter(Environment env,JwtProvider jwtProvider) {
        super(Config.class);
        this.env = env;
        this.jwtProvider=jwtProvider;
    }

    public static class Config {

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {


            String jwt = exchange.getRequest().getHeaders().get("Authorization").get(0).substring(7);   // 헤더의 토큰 파싱 (Bearer 제거)

            if (!isJwtValid(jwt)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"jwt token not valid");
            }

            return chain.filter(exchange);
        };
    }

    private boolean isJwtValid(String jwt) {
        boolean jwtVerify = false;

        String subject = null;

        try {
            jwtVerify = jwtProvider.verifyToken(jwt);
            subject = jwtProvider.getUserIdFromToken(jwt);
        } catch (Exception ex) {
            jwtVerify = false;
        }

        if (!jwtVerify || subject==null) {
            jwtVerify = false;
        }


        return jwtVerify;
    }





}