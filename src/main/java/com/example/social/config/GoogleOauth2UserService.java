package com.example.social.config;

import com.example.social.user.UserRegistrationService;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
// 구글은 OpenID Connect 1.0 를 이용하여 통신하기 때문에 OidcUserRequest 라고 쓰는 것을 유의하자.
public class GoogleOauth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
    private final UserRegistrationService userRegistrationService;


    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        final OidcUserService oidcUserService = new OidcUserService();

        // 유저 정보 조회를 하여 객체를 반환
        final OidcUser oidcUser = oidcUserService.loadUser(userRequest);

        final OAuth2AccessToken accessToken = userRequest.getAccessToken();

        // 기본적으로 스프링 부트에서 OAuth2 회원 정보를 가져오기 위한 getAttributes 메서드가 있다.
        String name = oidcUser.getAttributes().get("name").toString();
        String email = oidcUser.getAttributes().get("email").toString();

        userRegistrationService.requestRegistration(name,email);
        return new DefaultOidcUser(
                oidcUser.getAuthorities(),
                oidcUser.getIdToken(),
                oidcUser.getUserInfo()
        );
    }
}
