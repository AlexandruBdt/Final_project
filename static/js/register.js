const id_username = document.querySelector('#usernameField');
const feedBackArea = document.querySelector('.invalid-feedback');
const id_email = document.querySelector('#id_email');
const id_password = document.querySelector('#passwordField')
const emailfeedBackArea = document.querySelector('.invalid-email');
const usernameSucessOutput = document.querySelector('.usernameSucessOutput');
const showPasswordToggle = document.querySelector('.showPasswordToggle');
const submitBtn = document.querySelector('.submit-btn')


const handleToggleInput=(e)=>{
    if(showPasswordToggle.textContent==='SHOW'){
        showPasswordToggle.textContent = 'HIDE';

        id_password.setAttribute('type', 'text');
    }
    else{
        showPasswordToggle.textContent = 'SHOW';
        id_password.setAttribute('type', 'password');
    }
}

// Username Validation
id_username.addEventListener('keyup', (e) => {
    const usernameVal = e.target.value;

    usernameSucessOutput.style.display = "block";
    usernameSucessOutput.textContent = `Checking ${usernameVal}`;

    id_username.classList.remove('is-invalid');
    feedBackArea.style.display = 'none';

    if (usernameVal.length > 0){
        fetch('/authentication/validate-username', {
        body: JSON.stringify({username: usernameVal}),
        method: 'POST',
        }).then(res=>res.json()).then(data=>{
            usernameSucessOutput.style.display = "none";
            if(data.username_error){
                id_username.classList.add('is-invalid');
                feedBackArea.style.display = 'block';
                feedBackArea.innerHTML =  `<p>${data.username_error}</p>`;
                submitBtn.disabled = true;
            }
            else{
                submitBtn.removeAttribute('disabled');
            }
        });
    };

})


// Event show password
showPasswordToggle.addEventListener('click', handleToggleInput);