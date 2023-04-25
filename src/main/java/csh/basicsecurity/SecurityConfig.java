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

        http.formLogin()
//                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/loginPage")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler((req, res, auth) -> {
                    log.info("authentication success={}", auth.getName());
                    res.sendRedirect("/");
                })
                .failureHandler((req, res, exp) -> {
                    log.info("authentication failed={}", exp.getMessage());
                    res.sendRedirect("/loginPage");
                })
                .permitAll()
        ;

        return http.build();
    }

}
