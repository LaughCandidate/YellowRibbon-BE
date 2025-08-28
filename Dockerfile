FROM amd64/amazoncorretto:17

WORKDIR /app

COPY ./build/libs/YellowRibbon-BE-0.0.1-SNAPSHOT.jar /app/yellow-ribbon.jar

EXPOSE 8080

CMD ["java", "-Duser.timezone=Asia/Seoul", "-jar", "yellow-ribbon.jar"]