package guru.sfg.brewery.config;

import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/", "/webjars/**", "/login",
                                    "/resources/**")
                            .permitAll()
                            .antMatchers("/beers/find", "/beers*")
                            .permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**")
                            .permitAll()
                            .mvcMatchers(HttpMethod.GET,
                                    "/api/v1/beerUpc/{upc}")
                            .permitAll();
                })
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(
            AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("spring")
                .password("{bcrypt}$2a$10$7RkY26kT"
                        + ".tL6yw631au1he772TmEeYU1VBW9GxE1WI8fPNQo.KaT2")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password(
                        "{sha256}8e20712fa11eb49a4d3d6fc969306666433d78a549cb77134cd7dd66bbdb00fc9c1fc7b38d8d935e")
                .roles("USER")
                .and()
                .withUser("scott")
                .password("{bcrypt15}$2a$15$UIbMw2wLlIxVs9APPi4cY.WFkMLIgwzzDgij3PnXac6vztvFgWUoq")
                .roles("CUSTOMER");

    }

    /* @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin = User
                .withDefaultPasswordEncoder()
                .username("spring")
                .password("guru")
                .roles("ADMIN")
                .build();

        UserDetails user = User
                .withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }*/


}
