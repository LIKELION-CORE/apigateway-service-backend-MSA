FROM openjdk:11
COPY ./target/apigateway-service-0.0.1-SNAPSHOT.jar application.jar
ENV TZ=Asia/Seoul
EXPOSE 8000


#ENTRYPOINT ["java","-jar","-DSpring.profiles.active=prod","/application.jar"]

ENTRYPOINT ["java", "-jar", "-Dspring.config.name=bootstrap", "/application.jar"]

#ENTRYPOINT ["java","-jar","/application.jar"]
# ENTRYPOINT ["java","-jar", "-Djasypt.encryptor.password=${JASYPT_KEY}", "/application.jar"]
