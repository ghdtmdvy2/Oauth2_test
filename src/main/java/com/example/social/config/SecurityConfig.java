package com.example.social.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

import java.sql.ClientInfoStatus;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final Environment environment; // 각 환경에 대한 설정 변경이 필요하기 위해 가져옴.
    private final String registration = "spring.security.oauth2.client.registration."; // facebook과 google의 커스텀 마이징을 위한 yml 파일 가져오기.
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests(authorize -> authorize
                        .antMatchers("/login","/index").permitAll()
                        .anyRequest().authenticated())

                .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .authorizedClientService(auth2AuthorizedClientService())
                );
    }

    /*
    ClientRegistration에 대한 정보는 Authorization Server에서 해당 클라이언트의 정보가 필요할 때 사용한다.
    -> 즉 접속할 Provider에 대한 정보를 구현하는 것이다.
    */
    private ClientRegistration googleClientRegistration(){
        // yml 파일에서 spring.security.oauth2.client.registration.google.client-id 내용을 가져옴.
        final String clientId = environment.getProperty(registration + "google.client-id");
        // yml 파일에서 spring.security.oauth2.client.registration.google.client-secret 내용을 가져옴.
        final String clientSecret = environment.getProperty(registration + "google.client-secret");

        return CommonOAuth2Provider
                .GOOGLE
                .getBuilder("google")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
    }

    private ClientRegistration facebookClientRegistration(){
        // yml 파일에서 spring.security.oauth2.client.registration.facebook.client-id 내용을 가져옴.
        final String clientId = environment.getProperty(registration + "facebook.client-id");
        // yml 파일에서 spring.security.oauth2.client.registration.facebook.client-secret 내용을 가져옴.
        final String clientSecret = environment.getProperty(registration + "facebook.client-secret");

        return CommonOAuth2Provider
                .FACEBOOK
                .getBuilder("facebook")
                .clientId(clientId)
                .clientSecret(clientSecret)
                // 요청 엑세스 권한 수집 추가
                .scope(
                        "public_profile",
                        "email", // 이메일 수집
                        "user_birthday", // 생년월일 수집
                        "user_gender" // 성별 수집
                )
                // 커스텀 마이징을 통해 원래 email만 수집 되던 것을 gender, birthday를 추가한 것을 볼 수 있다.
                .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,picutre,gender,birthday")
                .build();
    }
    // 실제 토큰과 OAuth 와 통신
    @Bean
    public OAuth2AuthorizedClientService auth2AuthorizedClientService(){
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        // 각 facebook, google의 provider에 대한 정보를 list로 저장.
        final List<ClientRegistration> clientRegistrations = Arrays.asList(
                googleClientRegistration(),
                facebookClientRegistration()
        );
        // 각 provider를 ClientRegistrationRepository 에다가 저장.
        // ClientRegistrationRepository : ClientRegistration에 대한 정보를 저장하는 저장소.
        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }
}
