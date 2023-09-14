package ra.security.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ra.security.security.jwt.JwtEntryPoint;
import ra.security.security.jwt.JwtProvider;
import ra.security.security.jwt.JwtTokenFilter;
import ra.security.security.user_principle.UsertDetailService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)// phan quyen truc tiep tren component
public class WebsecurityConfig extends WebSecurityConfigurerAdapter {
    public final Logger loggger = LoggerFactory.getLogger(WebsecurityConfig.class);
    @Autowired
    private UsertDetailService detailService;
    @Autowired
    private JwtEntryPoint jwtEntryPoint;
    @Autowired
    private JwtTokenFilter jwtTokenFilter;


    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth.userDetailsService(detailService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // cau hinh phan quyen duong dan
         http.cors().and().csrf().disable() // tat cau hinh csrf
                 .authorizeHttpRequests()
                 .antMatchers("/api/v4/auth/**").permitAll()
                 .anyRequest().authenticated()
                 .and()
                 .exceptionHandling().authenticationEntryPoint(jwtEntryPoint)// cac duong dan khac phai duoc xac thuc
                 .and()
                 .sessionManagement()
                 .sessionCreationPolicy(SessionCreationPolicy.STATELESS); // yeu cau nguoi dung luon xac thuc bang ss
        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



}
