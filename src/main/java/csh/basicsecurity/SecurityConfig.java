package csh.basicsecurity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

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

        return http.build();
    }

}
