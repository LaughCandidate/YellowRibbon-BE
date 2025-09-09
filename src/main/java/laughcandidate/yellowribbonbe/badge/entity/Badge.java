package laughcandidate.yellowribbonbe.badge.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import laughcandidate.yellowribbonbe.mission.entity.Mission;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@Table(name = "BADGE")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Badge extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "badge_id")
    private Long id;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "category")
    private Category category;

    @OneToMany(mappedBy = "badge", fetch = FetchType.LAZY)
    private List<Mission> missions;

}
