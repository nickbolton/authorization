package com.tubebreakup.authorization.model.userToken;

import com.tubebreakup.model.BaseModel;
import io.swagger.annotations.ApiModel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Type;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Calendar;
import java.util.Date;

@ApiModel(description = "UserToken model object")
@Entity
@Getter
@Setter
@EntityListeners(AuditingEntityListener.class)
@Table(indexes = {
        @Index(name = "user_token_email_tok_idx", columnList = "email, token"),
        @Index(name = "user_token_email_type_idx", columnList = "email, type"),
        @Index(name = "user_token_idx", columnList = "token")
} ,
uniqueConstraints = { @UniqueConstraint(name = "email_type_uniq", columnNames = {"email", "type"}) })
public class UserToken extends BaseModel {

  private static final long serialVersionUID = -513175044924671937L;

  private static final int MAX_TOKEN_SIZE = 1024;
  private static final int MAX_PAYLOAD_SIZE = 2048;

  @Email
  @NotNull
  private String email;
  
  @NotNull
  @Lob
  @Type(type = "org.hibernate.type.TextType")
  @Column(unique = true)
  @Size(max = MAX_TOKEN_SIZE)
  private String token;

  @Lob
  @Type(type = "org.hibernate.type.TextType")
  @Size(max = MAX_TOKEN_SIZE)
  @Column(unique = true)
  private String refreshToken;

  @Lob
  @Type(type = "org.hibernate.type.TextType")
  @Size(max = MAX_PAYLOAD_SIZE)
  private String payload;

  @NotNull
  @Enumerated(value = EnumType.STRING)
  @Column(length = 20)
  private UserTokenType type;

  @NotNull
  private Date expirationDate;
  
  public void resetVerificationExpiryDate(int expiryTimeInMinutes) {
    Calendar cal = Calendar.getInstance();
    cal.setTime(new Date(cal.getTime().getTime()));
    cal.add(Calendar.MINUTE, expiryTimeInMinutes);
    this.expirationDate = new Date(cal.getTime().getTime());
  }

  public Boolean isExpired() {
    return expirationDate.getTime() <= new Date().getTime();
  }

  public UserToken(String email, String token, String refreshToken, String payload, UserTokenType type, Date expirationDate) {
    super();
    this.email = email;
    this.token = token;
    this.refreshToken = refreshToken;
    this.payload = payload;
    this.type = type;
    this.expirationDate = expirationDate;
  }
  
  protected UserToken() {
    super();
  }
}
