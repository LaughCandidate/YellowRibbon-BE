package laughcandidate.yellowribbonbe.yellowRibbon.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@Table(name = "YELLOW_RIBBON_BENEFIT")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class YellowRibbonBenefit extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "yellow_ribbon_benefit_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "yellow_ribbon_id", nullable = false)
    private YellowRibbon yellowRibbon;

    @Column(name = "name", length = 255, nullable = false)
    private String name;

    @Column(name = "description", length = 255)
    private String description;

    @Column(name = "link_url", length = 255)
    private String linkUrl;

}
