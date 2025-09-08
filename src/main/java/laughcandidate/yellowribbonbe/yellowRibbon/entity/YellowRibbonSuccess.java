package laughcandidate.yellowribbonbe.yellowRibbon.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import laughcandidate.yellowribbonbe.user.entity.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "YELLOW_RIBBON_SUCCESS")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class YellowRibbonSuccess extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "yellow_ribbon_success_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "business_id", nullable = false)
    private Business business;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "yellow_ribbon_id", nullable = false)
    private YellowRibbon yellowRibbon;

    @Builder
    public YellowRibbonSuccess(User user, Business business, YellowRibbon yellowRibbon) {
        this.user = user;
        this.business = business;
        this.yellowRibbon = yellowRibbon;
    }
}
