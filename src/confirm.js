// components/EmailTemplate.js
const React = require('react');

const Confirmation = ({codePass }) => {
  // Define styles as JavaScript objects
  const styles = {
    emailContainer: {
      height: 'auto',
      width: '100%',
      display: 'flex',
      justifyContent: 'center', // Changed this to justifyContent for proper flex alignment
      alignItems: 'center',
    },
    emailContent: {
      background: 'whitesmoke',
      padding: '2vw 5vw',
      borderRadius: '1vw',
      color: 'gray',
      width: 'fit-content', // Ensure content width adapts
      margin: '0 auto', // Centering the emailContent
    },
    emailTitle: {
      textAlign: 'center',
      fontSize: '1.2vw',
      lineHeight: '1vw',
      color: '#4fc4d3',
      margin: '0 auto', // Centering the title
    },
    from: {
      textAlign: 'center',
      fontSize: '.8vw',
      color: '#4fc4d3',
      margin: '0 auto', // Centering the title
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
      // Add any specific styles for expiration note if needed
      color: '#c92424',
      fontSize: '.7vw',
      fontWeight: '500',
    },
  };

  return React.createElement('div', { style: styles.emailContainer },
      React.createElement('div', { style: styles.emailContent },
      React.createElement('div', { style: styles.resetImg },
        React.createElement('img', { src: 'https://2wave.io/skinmiso/EmailImgs/mail.png', alt: "Mail Image", style: styles.resetImgSize }) // added alt text for better accessibility
      ),
      React.createElement('h2', { style: styles.emailTitle }, "Email Verifictation"),
      React.createElement('h2', { style: styles.from }, "from SKINMISO Canada"),
      React.createElement('p', { style: styles.text }, "Thank you for registering with Skinmiso Canada! To complete your registration, please use the following 6-digit verification code:"),
      React.createElement('div', { style: styles.codeDiv },
        React.createElement('p', { style: styles.recoverytxt }, "Your Code"),
        React.createElement('h1', { style: styles.emailRecoveryCode }, codePass),
      ),
      React.createElement('p', { style: styles.emailExpirationNote }, "This code will expire in 1 day."),
      React.createElement('p', { style: styles.text }, "Enter this code on the verification page to confirm your email address and activate your account.If you did not request this code or did not create an account, please ignore this email."),
      React.createElement('p', { style: styles.text }, "Thank you for choosing SKINMISO Canada!"),
      React.createElement('p', { style: styles.text }, "Best Regards,", 
      React.createElement('br'), 
        "Skinmiso Canada"
      )
    )
  );
};

module.exports = Confirmation;
