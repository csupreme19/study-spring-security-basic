package csh.basicsecurity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .anyRequest().authenticated();

        http.formLogin();

        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler((req, res, auth) -> {
                    log.info("logout handler");
                })
                .logoutSuccessHandler((req, res, auth) -> {
                    res.sendRedirect("/login");
                    log.info("logout success");
                })
                .deleteCookies("remember-me")
        ;

        http.rememberMe()
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(60 * 60 * 24 * 14)
                .userDetailsService(userDetailsService);

        return http.build();
    }

}
