package ra.security.service;

import ra.security.model.domain.Users;
import ra.security.model.dto.request.FormSignUpDto;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public interface IUserService {
    List<Users> listUsers();

    Optional<Users> findByUserName(String userName);

    Users save(FormSignUpDto users);

    boolean existsByUserName(String userName);
}
