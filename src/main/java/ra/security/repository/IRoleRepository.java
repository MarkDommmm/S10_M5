package ra.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ra.security.model.domain.Role;
import ra.security.model.domain.RoleName;

import java.util.Optional;

public interface IRoleRepository extends JpaRepository<Role, Long> {
    //Tim kiem theo role name
    Optional<Role> findByRoleName(RoleName roleName);
}
