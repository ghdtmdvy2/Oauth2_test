package com.example.social.config;

import com.example.social.user.UserRegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class FacebookOauth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserRegistrationService userRegistrationService;


    // API를 통신해서 회원 정보를 가져오는 곳
    // 즉 구글 로그인 했을 때 회원 정보를 가져오는 곳.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        final OAuth2UserService<OAuth2UserRequest, OAuth2User> userService = new DefaultOAuth2UserService();

        // 유저 정보 조회를 하여 객체를 반환
        final OAuth2User oAuth2User = userService.loadUser(userRequest);

        // 기본적으로 스프링 부트에서 OAuth2 회원 정보를 가져오기 위한 getAttributes 메서드가 있다.
        final String name = oAuth2User.getAttributes().get("name").toString();
        final String email = oAuth2User.getAttributes().get("email").toString();

        // name과 email을 가져와 회원가입을 시키게 만듦.
        userRegistrationService.requestRegistration(name,email);

        return new DefaultOAuth2User(
                oAuth2User.getAuthorities(),
                oAuth2User.getAttributes(),
                "id"
        );
    }
}
