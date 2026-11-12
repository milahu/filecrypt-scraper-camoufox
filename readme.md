# filecrypt-scraper-camoufox

decrypt filecrypt.cc link containers with a headless firefox browser in python

## limitations

- solving the cutcaptcha fails in about 10% of all cases,
  where cutcaptcha increases the difficulty so the user has to solve the captcha,
  for example by dragging two puzzle pieces to their expected positions.
  so running the scraper in `headful` mode is a good idea
