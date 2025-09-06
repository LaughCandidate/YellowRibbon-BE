package laughcandidate.yellowribbonbe.badge.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "BADGE")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Badge extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "bagde_id")
    private Long id;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "category")
    private Category category;

}
