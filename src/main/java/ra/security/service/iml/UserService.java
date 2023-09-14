package ra.security.service.iml;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ra.security.model.domain.Role;
import ra.security.model.domain.RoleName;
import ra.security.model.domain.Users;
import ra.security.model.dto.request.FormSignUpDto;
import ra.security.repository.IUserRepository;
import ra.security.service.IUserService;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService implements IUserService {
    @Autowired
    private IUserRepository userRepository;
    @Autowired
    private RoleService roleService;
    private PasswordEncoder passwordEncoder;

    @Override
    public List<Users> listUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<Users> findByUserName(String userName) {
        return userRepository.findByUsername(userName);
    }

    @Override
    public Users save(FormSignUpDto form) {
        if (userRepository.existsByUsername(form.getUsername())) {
            throw new RuntimeException("User already exists");
        }
        // lay ra danh sach cac quyen va chuyen thanh doi tuong Users
        Set<Role> roles = new HashSet<>();
        if (form.getRoles() == null || form.getRoles().isEmpty()) {
            roles.add(roleService.findByRoleName(RoleName.ROLE_USER));
        } else {
            form.getRoles().stream().forEach(
                    role -> {
                        switch (role) {
                            case "ADMIN":
                                roles.add(roleService.findByRoleName(RoleName.ROLE_ADMIN));
                            case "USER":
                                roles.add(roleService.findByRoleName(RoleName.ROLE_USER));
                            case "SELLER":
                                roles.add(roleService.findByRoleName(RoleName.ROLE_SELLER));
                            default:


                        }
                    }
            );
        }


        Users users = Users.builder()
                .name(form.getName())
                .username(form.getUsername())
                .password(passwordEncoder.encode(form.getPassword()))
                .status(true)
                .roles(roles)
                .build();
        return users;
    }

    @Override
    public boolean existsByUserName(String userName) {
        return userRepository.existsByUsername(userName);
    }
}
