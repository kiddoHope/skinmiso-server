const React = require('react');

const Confirmation = ({codePass }) => {
  const styles = {
    emailContainer: {
      height: 'auto',
      width: '100%',
      display: 'flex',
      justifyContent: 'center', 
      alignItems: 'center',
    },
    emailContent: {
      background: 'whitesmoke',
      padding: '2vw',
      borderRadius: '1vw',
      color: 'gray',
      width: 'fit-content',
      margin: '0 auto', 
    },
    emailTitle: {
      textAlign: 'center',
      fontSize: '1.2vw',
      lineHeight: '1vw',
      color: '#4fc4d3',
      margin: '0 auto', 
    },
    from: {
      textAlign: 'center',
      fontSize: '.8vw',
      color: '#4fc4d3',
      margin: '0 auto', 
    },
    resetImg: {
      display: 'flex',
      width: 'fit-content', 
      justifyContent: 'center',
      padding: '1vw 0',
      margin: '0 auto', 
    },
    resetImgSize: {
      height: 'auto',
      width: '10vw',
    },
    codeDiv: {
        textAlign: 'center',
        padding: '1vw',
        width: '100%',
        boxSizing: 'border-box',
        borderRadius: '1vw'
    },
    user:{
        color: 'black',
        fontSize: '.8vw',
        fontWeight: '700',
    },
    recoverytxt: {
        color: 'gray',
        fontSize: '.7vw',
        margin: '0'
    },
    text: {
        color: 'gray',
        fontSize: '.65vw',
        width:'20vw'
    },
    emailRecoveryCode: {
      color: '#4fc4d3',
      fontSize: '1.5vw',
      fontWeight: '800',
      margin: '0'
    },
    emailExpirationNote: {
      color: '#c92424',
      fontSize: '.7vw',
      fontWeight: '500',
    },
  };

  return React.createElement('div', { style: styles.emailContainer },
      React.createElement('div', { style: styles.emailContent },
      React.createElement('div', { style: styles.resetImg },
        React.createElement('img', {
          src: 'https://2wave.io/skinmiso/EmailImgs/reset-password.png',
          alt: "Reset Password Image",
          style: styles.resetImgSize
        })
      ),
      React.createElement('h2', { style: styles.emailTitle }, "Password Reset Request"),
      React.createElement('h2', { style: styles.from }, "from SKINMISO Canada"),
      React.createElement('p', { style: styles.text }, "We received a request to reset the password for your account. Use the 6-digit verification code below to reset your password:"),
      React.createElement('div', { style: styles.codeDiv },
        React.createElement('p', { style: styles.recoverytxt }, "Your Reset Code"),
        React.createElement('h1', { style: styles.emailRecoveryCode }, codePass),
      ),
      React.createElement('p', { style: styles.emailExpirationNote }, "This code will expire in 1 day."),
      React.createElement('p', { style: styles.text }, "If you did not request a password reset, please ignore this email or contact support if you have concerns."),
      React.createElement('p', { style: styles.text }, "Thank you for using SKINMISO Canada!"),
      React.createElement('p', { style: styles.text }, "Best Regards,",
        React.createElement('br'),
        "The SKINMISO Canada Team"
      )
    )
  );
};

module.exports = Confirmation;
