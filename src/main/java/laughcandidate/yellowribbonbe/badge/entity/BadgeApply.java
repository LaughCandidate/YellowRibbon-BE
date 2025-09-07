package laughcandidate.yellowribbonbe.badge.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.user.entity.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "BADGE_APPLY")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class BadgeApply extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "badge_apply_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "badge_id", nullable = false)
    private Badge badge;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "business_id", nullable = false)
    private Business business;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "status")
    private Status status;

    @Builder
    public BadgeApply(User user, Badge badge, Business business, Status status) {
        this.user = user;
        this.badge = badge;
        this.business = business;
        this.status = status;
    }
}
