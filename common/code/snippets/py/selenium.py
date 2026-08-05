#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import requests
import csv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

driver = webdriver.Chrome()
driver.get('https://www.usta.com/en/home/play/facility-listing.html?searchTerm=&distance=5000000000&address=Palo%20Alto,%20%20CA')
wait = WebDriverWait(driver, 8)

links = []

while True:
    new_links = wait.until(EC.visibility_of_all_elements_located((By.LINK_TEXT, "MORE INFO")))
    links.extend([link.get_attribute("href") for link in new_links])

    try:
        next_button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "li[title='Next page']>a")))
        next_button.click()
    except TimeoutException:
        break
    wait.until(EC.staleness_of(new_links[-1]))
