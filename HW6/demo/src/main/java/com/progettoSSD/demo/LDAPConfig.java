package com.progettoSSD.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.ldap.EmbeddedLdapServerContextSourceFactoryBean;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

@Configuration
public class LDAPConfig {

    @Bean
    public EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
        return EmbeddedLdapServerContextSourceFactoryBean.fromEmbeddedLdapServer();
    }

    @Bean
    public AuthenticationManager ldapAuthenticationManager(BaseLdapPathContextSource contextSource, 
                                                            LdapAuthoritiesPopulator authorities) {
        LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
        factory.setUserDnPatterns("uid={0},ou=people,dc=springframework,dc=org");
        factory.setLdapAuthoritiesPopulator(authorities);
        return factory.createAuthenticationManager();
    }
    

    @Bean
    LdapAuthoritiesPopulator authorities(BaseLdapPathContextSource contextSource) {
        String groupSearchBase = "ou=groups,dc=springframework,dc=org";
        DefaultLdapAuthoritiesPopulator authorities =
            new DefaultLdapAuthoritiesPopulator(contextSource, groupSearchBase);
        authorities.setGroupSearchFilter("member={0}");
        return authorities;
    }
}
