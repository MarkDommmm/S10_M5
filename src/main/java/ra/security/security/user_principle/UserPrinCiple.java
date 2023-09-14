package ra.security.security.user_principle;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import ra.security.model.domain.Role;
import ra.security.model.domain.Users;


import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserPrinCiple implements UserDetails {

    private Long id;
    private String name;

    private String username;
    @JsonIgnore
    private String password;
    private Boolean status;
    private Collection<? extends GrantedAuthority> authorities;

    public static UserPrinCiple build(Users users) {
        List<GrantedAuthority> list = users.getRoles().stream().map(
                role ->
                        new SimpleGrantedAuthority(role.getRoleName().name())
        ).collect(Collectors.toList());
        return UserPrinCiple.builder()
                .id(users.getId())
                .name(users.getName())
                .username(users.getUsername())
                .password(users.getPassword())
                .authorities(list)
                .status(users.getStatus())
                .build();
    }

    private Set<Role> roles = new HashSet<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
